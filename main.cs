﻿/* [fkelava 17/5/23 02:48]
 * A shitty, quick tool to emit (mostly?!) valid C# from a Ghidra symbol JSON.
 */

using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace Fahrenheit.Tools.STEP;

// https://csvjson.com/csv2json - PARSE NUMBERS: OFF, PARSE JSON: OFF, OUTPUT: ARRAY
internal sealed record FhGhidraSymbolDecl(
    string Name,
    string Location,
    string Signature,
    string Source,
    string Type,
    string FuncName,
    string CallConv,
    string Namespace);

internal ref struct FhMethodLocal {
    public ReadOnlySpan<char>           ReturnType;
    public ReadOnlySpan<char>           FunctionName;
    public List<FhSymbolParameterLocal> Parameters;
}

internal struct FhSymbolParameterLocal(ReadOnlySpan<char> ParameterType, ReadOnlySpan<char> ParameterName) {
    public string ParameterType = new string(ParameterType);
    public string ParameterName = new string(ParameterName);
}

internal class Program {
    private static Dictionary<string, string> _type_map = [];

    static void Main(string[] args) {
        Option<string> opt_src_path     = new Option<string>("--src")  { Description = "Set the path to the source file."                    };
        Option<string> opt_dest_path    = new Option<string>("--dest") { Description = "Set the folder where the C# file should be written." };
        Option<string> opt_typemap_path = new Option<string>("--map")  { Description = "Set the path to a Ghidra -> Fh type map."            };

        opt_src_path    .Required = true;
        opt_dest_path   .Required = true;
        opt_typemap_path.Required = false;

        RootCommand root_cmd = new RootCommand("Process a Ghidra symbol table and create a C# code file.") {
            opt_src_path,
            opt_dest_path,
            opt_typemap_path
        };

        ParseResult argparse_result = root_cmd.Parse(args);

        string src_file_path = argparse_result.GetValue(opt_src_path)     ?? "";
        string dest_path     = argparse_result.GetValue(opt_dest_path)    ?? "";
        string typemap_path  = argparse_result.GetValue(opt_typemap_path) ?? "";

        string dest_file_path = Path.Join(dest_path, $"call-{Guid.NewGuid()}.g.cs");
        _emit_symtable(src_file_path, dest_file_path, typemap_path);
        return;
    }

    // TODO: fix fix fix fix fix fix fix
    private static bool _is_interpretable(FhGhidraSymbolDecl symbol) {
        return  symbol.Type      == "Function"     &&
               (symbol.Source    == "USER_DEFINED" || 
                symbol.Source    == "IMPORTED")    &&
                symbol.Namespace == "Global"       && // might be a removable restriction
               !symbol.Name.Contains("operator")   && // ignore operator.new, operator.delete
               !symbol.Name.Contains("Unwind@")    && // ignore Unwind@{ADDR} thunks
               !symbol.Signature.Contains('.')     && // ignore vararg functions
               !symbol.Signature.Contains(':')     && // ignore anything that even vaguely resembles a C++ namespace
               !symbol.Signature.Contains('-');
    }

    private static string _unescape(string symtable_json) {
        return symtable_json.Replace("\\\\,",  ",")  // Ghidra CSV unescape
                            .Replace("\"\\",   "" )  // Ghidra CSV unescape
                            .Replace(" *",     "*")  // Ghidra "float * param_1" -> "float* param_1"
                            .Replace("+",      "" );
    }

    private static ReadOnlySpan<char> _translate_callconv(ReadOnlySpan<char> call_conv) {
        return call_conv switch {
            "__thiscall" => "[UnmanagedFunctionPointer(CallingConvention.ThisCall)]",
            "__cdecl"    => "[UnmanagedFunctionPointer(CallingConvention.Cdecl)]",
            "__stdcall"  => "[UnmanagedFunctionPointer(CallingConvention.StdCall)]",
            "__fastcall" => "[UnmanagedFunctionPointer(CallingConvention.FastCall)]",
            "unknown"    => "[UnmanagedFunctionPointer(CallingConvention.Cdecl)]",
            _            => throw new Exception($"FH_E_FNTBL_CALLCONV_UNKNOWN: {call_conv}")
        };
    }

    // TODO: fix
    private static ReadOnlySpan<char> _translate_param_type(string param_type) {
        return _type_map.TryGetValue(param_type, out string? mapped_type)
            ? mapped_type
            : "nint";
    }

    // TODO: fix
    private static ReadOnlySpan<char> _translate_return_type(string return_type) {
        return return_type switch {
            "void"      => "void",
            "undefined" => "void",
            _           => _translate_param_type(return_type)
        };
    }

    // TODO: fix
    private static ReadOnlySpan<char> _translate_param_name(ReadOnlySpan<char> param_name) {
        return param_name switch {
            "this" => "_this",
            _      => param_name
        };
    }

    private static string _emit_params(FhMethodLocal method) {
        List<string> param_str = [];

        foreach (FhSymbolParameterLocal param in method.Parameters) {
            param_str.Add($"{_translate_param_type(param.ParameterType)} {_translate_param_name(param.ParameterName)}");
        }

        return $"({string.Join(", ", param_str)})";
    }

    private static string _emit_method(FhMethodLocal method, FhGhidraSymbolDecl symbol) {
        int addr = int.Parse(symbol.Location, NumberStyles.HexNumber, CultureInfo.InvariantCulture) - 0x400000;

        return $"""
    // Original after pruning:
    // {symbol.CallConv} {symbol.Signature} at {symbol.Location}

    {_translate_callconv(symbol.CallConv)}
    public unsafe delegate {method.ReturnType} {method.FunctionName}{_emit_params(method)};
    public const nint __addr_{symbol.Name} = 0x{addr.ToString("X")};

""";
    }

    private static string _emit_prologue() {
        return $$"""
/* [step {{DateTime.UtcNow.ToString("dd/M/yy HH:mm")}}]
 * This file was generated by Fahrenheit.Tools.STEP (https://github.com/peppy-enterprises/fh-tools-step/).
 *
 * Its purpose is to provide auto-generated delegates to allow you to call or hook game functions without having
 * to go through an extensive reverse-engineering process. These are, for the time being, quite rudimentary;
 * many parameters whose types are known to us are still mapped only to `nint`.
 *
 * The presence of a delegate or method signature in this file does not imply it has been tested. You have been warned.
 *
 * To improve the call map quality, add new entries to `typemap.json` in the STEP source code or annotate further
 * methods in Ghidra. Every so often, STEP generation will be rerun and Fahrenheit updated with the result.
 */

namespace Fahrenheit.Core;

public static class FhCall {

""";
    }

    private static void _emit_symtable(string src_path, string dest_path, string typemap_path) {
        Stopwatch perf = Stopwatch.StartNew();

        try {
            string type_map_str = File.ReadAllText(typemap_path);
            _type_map = JsonSerializer.Deserialize<Dictionary<string, string>>(type_map_str) ?? [];
        }
        catch {
            Console.WriteLine("Type map load failed or type map path not specified.");
        }

        // Required because Ghidra exports to CSV, so they have to escape commas strongly.
        string               unescaped_json      = _unescape(File.ReadAllText(src_path));
        FhGhidraSymbolDecl[] symbol_declarations = JsonSerializer.Deserialize<FhGhidraSymbolDecl[]>(unescaped_json) ?? [];

        // Reusable symbol locals.
        List<FhSymbolParameterLocal> parameters = [];
        FhMethodLocal                method     = new FhMethodLocal();

        // Actual file contents.
        StringBuilder sb = new(_emit_prologue());

        foreach (FhGhidraSymbolDecl symbol in symbol_declarations) {
            if (!_is_interpretable(symbol)) {
                sb.AppendLine($"    // Symbol skipped (deemed uninterpretable or explicitly rejected):");
                sb.AppendLine($"    // {symbol.CallConv} {symbol.Signature} at {symbol.Location}");
                sb.AppendLine();
                continue;
            }

            // We lex the function signature in the form {RETURN_TYPE} {NAME}({PARAMETER_TYPE} {PARAMETER_NAME} ... );
            // !!! temporarily pessimized !!! fixme later !!!
            string[] tokens = symbol.Signature.Split([ ' ', ',', '(', ')' ], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            string original_return_type   = tokens[0]; // We will translate this later.
            string original_function_name = tokens[1]; // Preserved verbatim.

            for (int i = 2; i < tokens.Length - 1; ) {
                ReadOnlySpan<char> original_parameter_type = tokens[i++];
                ReadOnlySpan<char> original_parameter_name = tokens[i++];

                parameters.Add(new FhSymbolParameterLocal(original_parameter_type, original_parameter_name));
            }

            method.ReturnType   = _translate_return_type(original_return_type);
            method.FunctionName = original_function_name;
            method.Parameters   = parameters;

            sb.AppendLine(_emit_method(method, symbol));
            parameters.Clear();
        }

        sb.AppendLine("}");

        File.WriteAllText(dest_path, sb.ToString());
        Console.WriteLine($"Call map emitted to {dest_path} in {perf.Elapsed}.");
    }
}
