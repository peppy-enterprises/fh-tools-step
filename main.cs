/* [fkelava 17/5/23 02:48]
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

using CsvHelper;
using CsvHelper.Configuration.Attributes;

namespace Fahrenheit.Tools.STEP;

// In Ghidra, select fields:
// Name, Location, Function Signature, Symbol Source,
// Symbol Type, Function Name, Call Conv, Namespace
internal struct FhMethodDecl {
    [Index(0)] public string Name      { get; set; }
    [Index(1)] public string Location  { get; set; }
    [Index(2)] public string Signature { get; set; }
    [Index(3)] public string Source    { get; set; }
    [Index(4)] public string Type      { get; set; }
    [Index(5)] public string FuncName  { get; set; }
    [Index(6)] public string CallConv  { get; set; }
    [Index(7)] public string Namespace { get; set; }
}

// In Ghidra, select fields: Name, Location, Type, Data Type, Namespace, Source
// Filter by: Source - User Defined, Type - Data Label
internal struct FhDataLabelDecl {
    [Index(0)] public string Name      { get; set; }
    [Index(1)] public string Location  { get; set; }
    [Index(2)] public string Type      { get; set; }
    [Index(3)] public string DataType  { get; set; }
    [Index(4)] public string Namespace { get; set; }
    [Index(5)] public string Source    { get; set; }
}

internal ref struct FhMethodExtraData {
    public ReadOnlySpan<char>          ReturnType;
    public List<FhMethodParameterData> Parameters;
}

internal struct FhMethodParameterData(ReadOnlySpan<char> ParameterType, ReadOnlySpan<char> ParameterName) {
    public string ParameterType = new string(ParameterType);
    public string ParameterName = new string(ParameterName);
}

internal class Program {
    private static Dictionary<string, string> _type_map = [];

    private static void Main(string[] args) {
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

        string src_path      = argparse_result.GetValue(opt_src_path)     ?? "";
        string dest_path     = argparse_result.GetValue(opt_dest_path)    ?? "";
        string typemap_path  = argparse_result.GetValue(opt_typemap_path) ?? "";

        string dest_file_path = Path.Join(dest_path, $"call-{Guid.NewGuid()}.g.cs");
        _emit_symtable(src_path, dest_file_path, typemap_path);
    }

    /// <summary>
    /// Determines whether a specific method declaration provided by Ghidra should be interpreted.
    /// </summary>
    /// <param name="method">The method declaration to be checked.</param>
    /// <returns>Whether the provided method declaration should be interpreted.</returns>
    private static bool _method_is_interpretable(FhMethodDecl method) {
        return  method is {
                    Type: "Function",
                    Source: "USER_DEFINED" or "IMPORTED",
                    Namespace: "Global", // might be a removable restriction
                } &&
                !method.Name.Contains("operator") && // ignore operator.new, operator.delete
                !method.Name.Contains("Unwind@") &&  // ignore Unwind@{ADDR} thunks
                !method.Signature.Contains('.') &&   // ignore vararg functions
                !method.Signature.Contains(':') &&   // ignore anything that even vaguely resembles a C++ namespace
                !method.Signature.Contains('-');
    }

    /// <summary>
    /// Modified provided methods, fixing formatting and undoing Ghidra's CSV escapes.
    /// </summary>
    /// <param name="methods">Ghidra-provided method declarations to format and unescape.</param>
    //TODO: Maybe should be called `_format_methods`
    private static void _fix_methods(Span<FhMethodDecl> methods) {
        for (int i = 0; i < methods.Length; i++) {
            methods[i].Signature = methods[i].Signature
                .Replace(" *"   , "*") // Ghidra "float * param_1" -> "float* param_1"
                .Replace("\\,"  , ",") // Ghidra CSV unescape
                .Replace("\"\\" , "" );
        }
    }

    /// <summary>
    /// Convert from a C++/Ghidra calling convention specifier to the equivalent C# attribute for delegates.
    /// </summary>
    /// <param name="call_conv">The C++/Ghidra-style calling convention specifier.</param>
    /// <returns>An equivalent C# attribute applicable to delegates.</returns>
    /// <exception cref="ArgumentException">Thrown if the C++/Ghidra-style calling convention specifier is not recognized.</exception>
    //TODO: Maybe should be called `_method_map_callconv` or `_method_emit_callconv` (given `_method_emit_params`)?
    private static ReadOnlySpan<char> _method_translate_callconv(ReadOnlySpan<char> call_conv) {
        return call_conv switch {
            "__thiscall" => "[UnmanagedFunctionPointer(CallingConvention.ThisCall)]",
            "__cdecl"    => "[UnmanagedFunctionPointer(CallingConvention.Cdecl)]",
            "__stdcall"  => "[UnmanagedFunctionPointer(CallingConvention.StdCall)]",
            "__fastcall" => "[UnmanagedFunctionPointer(CallingConvention.FastCall)]",
            "unknown"    => "[UnmanagedFunctionPointer(CallingConvention.Cdecl)]",
            _ => throw new ArgumentException($"Encountered an unknown calling convention `{call_conv}` while parsing methods."),
        };
    }

    /// <summary>
    /// Applies the user-defined type map to a parameter type provided by Ghidra.
    /// </summary>
    /// <example>
    /// Putting <c>"undefined4": "uint"</c> in the type map
    /// will map Ghidra's <c>undefined4</c> type to C#'s <c>uint</c> type.
    /// </example>
    /// <param name="param_type">The string representation of a Ghidra parameter type.</param>
    /// <returns>The mapped parameter type.</returns>
    //TODO: Maybe should be called `_map_param_type`?
    private static ReadOnlySpan<char> _method_translate_param_type(string param_type) {
        return _type_map.GetValueOrDefault(param_type, "nint");
    }

    /// <summary>
    /// Applies the user-defined type map to a parameter type provided by Ghidra.<br/>
    /// Unlike <see cref="_method_translate_param_type"/>, accounts for <c>void</c>.
    /// </summary>
    /// <param name="return_type">The string representation of a Ghidra return type.</param>
    /// <returns>The mapped return type.</returns>
    //TODO: Maybe should be called `_map_return_type`?
    private static ReadOnlySpan<char> _method_translate_return_type(string return_type) {
        return return_type switch {
            "void"      => "void",
            "undefined" => "void",
            _           => _method_translate_param_type(return_type)
        };
    }

    /// <summary>
    /// Modifies a parameter name to not conflict with C# keywords.
    /// </summary>
    /// <param name="param_name">A parameter name to modify.</param>
    /// <returns>The modified parameter name.</returns>
    //TODO: Maybe should be called `_escape_param_name` or `_modify_param_name`?
    private static ReadOnlySpan<char> _method_translate_param_name(ReadOnlySpan<char> param_name) {
        /*TODO: Consider https://stackoverflow.com/a/44728184 or https://stackoverflow.com/a/44728208
                Something akin to `return cs.IsValidIdentifier(param_name) ? param_name : $"_{param_name}";`*/
        return param_name switch {
            "this" => "_this",
            _      => param_name,
        };
    }

    /// <summary>
    /// Translates a method's parameter list to a string with types and names mapped.
    /// </summary>
    /// <param name="method">The method to translate the parameter list of.</param>
    /// <returns>A string representation of the parameter list, valid as C# code.</returns>
    //TODO: Why doesn't this just take in a `List<FhMethodParameterData>`?
    private static string _method_emit_params(FhMethodExtraData method) {
        List<string> param_str = [];

        foreach (FhMethodParameterData param in method.Parameters) {
            param_str.Add($"{_method_translate_param_type(param.ParameterType)} {_method_translate_param_name(param.ParameterName)}");
        }

        return $"({String.Join(", ", param_str)})";
    }

    /// <summary>
    /// Converts a method and the associated Ghidra symbol declaration into valid C# code.
    /// </summary>
    /// <param name="method">A Ghidra-provided method.</param>
    /// <param name="method_data">The method data associated with the method.</param>
    /// <returns>A valid C# delegate declaration and associated function address constant.</returns>
    private static string _emit_method(FhMethodDecl method, FhMethodExtraData method_data) {
        int addr = Int32.Parse(method.Location, NumberStyles.HexNumber, CultureInfo.InvariantCulture) - 0x400000;

        /*TODO: Consider using a StringBuilder instead,
                the blank line at the end and the messy indentation are cons that should be weighted.*/
        return $"""
    // Original after pruning:
    // {method.CallConv} {method.Signature} at {method.Location}

    {_method_translate_callconv(method.CallConv)}
    public unsafe delegate {method_data.ReturnType} {method.FuncName}{_method_emit_params(method_data)};
    public const nint __addr_{method.Name} = 0x{addr:X};

""";
    }

    /// <summary>
    /// Converts a global symbol provided by Ghidra
    /// </summary>
    /// <param name="global">A global symbol provided by Ghidra</param>
    /// <returns>A valid C# const declaration for the given global</returns>
    private static string _emit_global(FhDataLabelDecl global) {
        int addr = Int32.Parse(global.Location, NumberStyles.HexNumber, CultureInfo.InvariantCulture) - 0x400000;

        /*TODO: Consider using a StringBuilder instead,
                the blank line at the end and the messy indentation are cons that should be weighted.*/
        //TODO: Add a typed const declaration using the provided typemap json.
        return $"""
    // Original after pruning:
    // {global.DataType} {global.Name} at {global.Location}

    public const nint __addr_{global.Name} = 0x{addr:X};

""";
    }

    /// <summary>
    /// Return FhCall's introductory comment.
    /// </summary>
    /// <returns>An introductory comment.</returns>
    private static string _emit_prologue() {
        return $$"""
/* [step {{DateTime.UtcNow:dd/M/yy HH:mm}}]
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

"""; //TODO: Why does this return the first few lines of code *along* with the comment? These should ideally be separate.
    }

    /// <summary>
    /// Emits a C# code file to a specified path using exported Ghidra symbols and a user-defined typemap.
    /// </summary>
    /// <param name="src_path">
    ///     The path to the directory containing the Ghidra symbol exports.<br/>
    ///     The directory must contain appropriately exported <c>methods.csv</c> and <c>globals.csv</c>.
    /// </param>
    /// <param name="dest_path">The path to write the C# code file to.</param>
    /// <param name="typemap_path">The path to the user-defined typemap. Typemap must be a valid JSON.</param>
    private static void _emit_symtable(string src_path, string dest_path, string typemap_path) {
        Stopwatch perf = Stopwatch.StartNew();

        try {
            string type_map_str = File.ReadAllText(typemap_path);
            _type_map = JsonSerializer.Deserialize<Dictionary<string, string>>(type_map_str) ?? [];
        }
        catch {
            Console.WriteLine("Type map load failed or type map path not specified.");
        }

        string method_file_path = Path.Join(src_path, "methods.csv");
        string global_file_path = Path.Join(src_path, "globals.csv");

        FhMethodDecl[]    methods;
        FhDataLabelDecl[] globals;

        /*TODO: Should these be separate for readability's sake?
        * using (StreamReader method_reader = new StreamReader(method_file_path))
        * using (CsvReader    method_csv    = new CsvReader   (method_reader, CultureInfo.InvariantCulture)) {
        *     methods = [ .. method_csv.GetRecords<FhMethodDecl>() ];
        * }
        * * * * *
        * using (StreamReader global_reader = new StreamReader(global_file_path))
        * using (CsvReader    global_csv    = new CsvReader   (global_reader, CultureInfo.InvariantCulture)) {
        *     globals = [ .. global_csv.GetRecords<FhDataLabelDecl>() ];
        * }
        */
        using (StreamReader method_reader = new StreamReader(method_file_path))
        using (StreamReader global_reader = new StreamReader(global_file_path))
        using (CsvReader    method_csv    = new CsvReader   (method_reader, CultureInfo.InvariantCulture))
        using (CsvReader    global_csv    = new CsvReader   (global_reader, CultureInfo.InvariantCulture)) {
            methods = [ .. method_csv.GetRecords<FhMethodDecl>()    ];
            globals = [ .. global_csv.GetRecords<FhDataLabelDecl>() ];
        }

        _fix_methods(methods);

        // Reusable symbol locals.
        List<FhMethodParameterData> parameters  = [];
        FhMethodExtraData           method_data = new FhMethodExtraData();

        // Actual file contents.
        StringBuilder sb = new(_emit_prologue());

        foreach (FhMethodDecl method in methods) {
            if (!_method_is_interpretable(method)) {
                sb.AppendLine($"    // Symbol skipped (deemed uninterpretable or explicitly rejected):");
                sb.AppendLine($"    // {method.CallConv} {method.Signature} at {method.Location}");
                sb.AppendLine();
                continue;
            }

            // We lex the function signature in the form {RETURN_TYPE} {NAME}({PARAMETER_TYPE} {PARAMETER_NAME} ... );
            string[] tokens = method.Signature.Split(
                [ ' ', ',', '(', ')' ],
                StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries
            );

            string original_return_type   = tokens[0]; // We will translate this later.
            //TODO: Remove `+` from custom function names.
            string original_function_name = tokens[1]; // Preserved verbatim.

            for (int i = 2; i < tokens.Length - 1; i += 2) {
                ReadOnlySpan<char> original_parameter_type = tokens[i];
                ReadOnlySpan<char> original_parameter_name = tokens[i + 1];

                parameters.Add(new FhMethodParameterData(original_parameter_type, original_parameter_name));
            }

            method_data.ReturnType = _method_translate_return_type(original_return_type);
            method_data.Parameters = parameters;

            sb.AppendLine(_emit_method(method, method_data));
            parameters.Clear();
        }

        foreach (FhDataLabelDecl global in globals) {
            sb.AppendLine(_emit_global(global));
        }

        sb.AppendLine("}");

        File.WriteAllText(dest_path, sb.ToString());
        Console.WriteLine($"Call map emitted to {dest_path} in {perf.Elapsed}.");
    }
}
