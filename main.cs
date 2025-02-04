/* [fkelava 17/5/23 02:48]
 * A shitty, quick tool to emit (mostly?!) valid C# from a Ghidra symbol JSON.
 */

using System;
using System.Collections.Generic;
using System.CommandLine;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

using Fahrenheit.Core;

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
    static void Main(string[] args) {
        Option<string> opt_file_path = new Option<string>("--src", "Set the path to the source file.");
        Option<string> opt_dest_path = new Option<string>("--dest", "Set the folder where the C# file should be written.");

        opt_file_path.IsRequired = true;
        opt_dest_path.IsRequired = true;

        RootCommand root_cmd = new RootCommand("Process a Ghidra symbol table and create a C# code file.") {
            opt_file_path,
            opt_dest_path
        };

        root_cmd.SetHandler(FhSTEPMain, new FhSTEPArgsBinder(
            opt_file_path,
            opt_dest_path));

        root_cmd.Invoke(args);
        return;
    }

    static void FhSTEPMain(FhSTEPArgs config) {
        FhSTEPConfig.CLIRead(config);

        string dest_file_name = Path.Join(FhSTEPConfig.DestPath, $"call-{Guid.NewGuid()}.g.cs");
        _emit_symtable(dest_file_name);
    }

    // TODO: fix fix fix fix fix fix fix
    private static bool _is_interpretable(FhGhidraSymbolDecl symbol) {
        return  symbol.Type      == "Function"     &&
                symbol.Source    == "USER_DEFINED" &&
                symbol.Namespace == "Global"       && // might be a removable restriction
               !symbol.Name.Contains("operator")   && // ignore operator.new, operator.delete
               !symbol.Name.Contains("Unwind@")    && // ignore Unwind@{ADDR} thunks
               !symbol.Name.Contains("=^._.^=")    && // ignore temporarily mismarked functions
               !symbol.Signature.Contains('.')     && // ignore vararg functions
               !symbol.Signature.Contains(':')     && // ignore anything that even vaguely resembles a C++ namespace
               !symbol.Signature.Contains('!')     && // ignore OTHERWISE mismarked functions
               !symbol.Signature.Contains('?')     && // ignore OTHERWISE OTHERWISE mismarked functions
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
            _            => throw new Exception($"FH_E_FNTBL_CALLCONV_UNKNOWN: {call_conv}")
        };
    }

    // TODO: fix
    private static ReadOnlySpan<char> _translate_arg_type(ReadOnlySpan<char> arg_type) {
        if (arg_type.Contains('*')) return "nint";

        return arg_type switch {
            "void"       => "",
            "undefined"  => "nint",
            "undefined1" => "byte",
            "undefined2" => "ushort",
            "undefined4" => "uint",
            "undefined8" => "ulong",
            _            => "nint"
        };
    }

    // TODO: fix
    private static ReadOnlySpan<char> _translate_return_type(ReadOnlySpan<char> arg_type) {
        if (arg_type.Contains('*')) return "nint";

        return arg_type switch {
            "void" => "void",
            _      => _translate_arg_type(arg_type)
        };
    }

    // TODO: fix
    private static ReadOnlySpan<char> _translate_param_name(ReadOnlySpan<char> arg_name) {
        return arg_name switch {
            "this" => "_this",
            _      => arg_name
        };
    }

    private static string _emit_params(FhMethodLocal method) {
        StringBuilder sb = new StringBuilder("(");
        foreach (FhSymbolParameterLocal param in method.Parameters) {
            sb.Append($"{_translate_arg_type(param.ParameterType)} {_translate_param_name(param.ParameterName)}, ");
        }
        sb.Remove(sb.Length - 2, 2); // TODO: fix
        sb.Append(')');
        return sb.ToString();
    }

    private static string _emit_method(FhMethodLocal method, FhGhidraSymbolDecl symbol) {
        return $"""
    // Original after pruning: {symbol.CallConv} {symbol.Signature} at {symbol.Location}
    {_translate_callconv(symbol.CallConv)}
    public unsafe delegate {method.ReturnType} {method.FunctionName}{_emit_params(method)};
    public const nint __addr_{symbol.Name} = 0x{symbol.Location.ToUpperInvariant()};

""";
    }

    private static string _emit_prologue() {
        return $$"""
/* [step {{DateTime.UtcNow.ToString("dd/M/yy HH:mm")}}]
 * This file was generated by Fahrenheit.Tools.STEP (https://github.com/peppy-enterprises/fh-tools-step/).
 */

namespace Fahrenheit.Core;

public static class FhCall {

""";
    }

    private static void _emit_symtable(string dest_path) {
        Stopwatch perf = Stopwatch.StartNew();

        // Required because Ghidra exports to CSV, so they have to escape commas strongly.
        string               unescaped_json      = _unescape(File.ReadAllText(FhSTEPConfig.SrcPath));
        FhGhidraSymbolDecl[] symbol_declarations = JsonSerializer.Deserialize<FhGhidraSymbolDecl[]>(unescaped_json) ?? [];

        // Reusable symbol locals.
        List<FhSymbolParameterLocal> parameters = [];
        FhMethodLocal                method     = new FhMethodLocal();

        // Actual file contents.
        StringBuilder sb = new(_emit_prologue());

        foreach (FhGhidraSymbolDecl symbol in symbol_declarations) {
            if (!_is_interpretable(symbol)) {
                sb.AppendLine($"    // Symbol skipped (deemed uninterpretable): {symbol.CallConv} {symbol.Signature} at {symbol.Location}");
                sb.AppendLine();
                continue;
            }

            // We lex the function signature in the form {RETURN_TYPE} {NAME}({PARAMETER_TYPE} {PARAMETER_NAME} ... );
            FhTokenizer        tokenizer = new FhTokenizer(symbol.Signature, [ ' ', ',', '(', ')' ]);
            ReadOnlySpan<char> token_local;

            ReadOnlySpan<char> original_return_type   = tokenizer.GetNextToken(); // We will translate this later.
            ReadOnlySpan<char> original_function_name = tokenizer.GetNextToken(); // Preserved verbatim.

            while ((token_local = tokenizer.GetNextToken()) != ReadOnlySpan<char>.Empty) {
                ReadOnlySpan<char> original_parameter_type = token_local;
                ReadOnlySpan<char> original_parameter_name = tokenizer.GetNextToken();

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
