using System;
using System.CommandLine;
using System.CommandLine.Binding;
using System.IO;

namespace Fahrenheit.Tools.STEP;

internal static class FhSTEPConfig {
    public static string SrcPath     = string.Empty;
    public static string DestPath    = string.Empty;
    public static string TypeMapPath = string.Empty;

    public static void CLIRead(FhSTEPArgs args) {
        SrcPath     = args.SrcPath;
        DestPath    = Directory.Exists(args.DestPath) ? args.DestPath : throw new Exception("E_INVALID_DEST_DIR");
        TypeMapPath = args.TypeMapPath;
    }
}

internal sealed record FhSTEPArgs(string SrcPath,
                                  string DestPath,
                                  string TypeMapPath);

internal class FhSTEPArgsBinder : BinderBase<FhSTEPArgs> {
    private readonly Option<string> _opt_src_path;
    private readonly Option<string> _opt_dest_path;
    private readonly Option<string> _opt_typemap_path;

    public FhSTEPArgsBinder(Option<string> opt_file_path,
                            Option<string> opt_dest_path,
                            Option<string> opt_typemap_path) {
        _opt_src_path     = opt_file_path;
        _opt_dest_path    = opt_dest_path;
        _opt_typemap_path = opt_typemap_path;
    }

    protected override FhSTEPArgs GetBoundValue(BindingContext binding_context) {
        string src_path     = binding_context.ParseResult.GetValueForOption(_opt_src_path)     ?? throw new Exception("E_CLI_ARG_NULL");
        string dest_path    = binding_context.ParseResult.GetValueForOption(_opt_dest_path)    ?? throw new Exception("E_CLI_ARG_NULL");
        string typemap_path = binding_context.ParseResult.GetValueForOption(_opt_typemap_path) ?? throw new Exception("E_CLI_ARG_NULL");

        return new FhSTEPArgs(src_path, dest_path, typemap_path);
    }
}
