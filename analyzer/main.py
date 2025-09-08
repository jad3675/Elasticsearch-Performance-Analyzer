import tkinter as tk
from .cli import setup_parser, handle_cli
from .ui.main_window import ElasticsearchAnalyzer

def main():
    """Main entry point for the application."""
    parser = setup_parser()
    args = parser.parse_args()

    # Validate CLI args
    if args.run or args.export_json:
        if not (args.cloud_id or args.url):
            parser.error("Connection details (--cloud-id or --url) are required for CLI runs.")
        if not (args.api_key or (args.user and args.password)):
             parser.error("Authentication details (--api-key or --user/--password) are required for CLI runs.")
        if args.user and not args.password:
            parser.error("--password is required when --user is provided.")
        
        handle_cli(args)
    else:
        root = tk.Tk()
        app = ElasticsearchAnalyzer(root, cli_args=args)
        root.mainloop()

if __name__ == "__main__":
    # This allows running the app with `python -m analyzer.main`
    main()