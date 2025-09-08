def format_table(headers, rows, title=None):
    """Create a formatted ASCII table with headers and rows"""
    # Calculate column widths
    col_widths = {header: len(header) for header in headers}
    for row in rows:
        for header, value in zip(headers, row):
            col_widths[header] = max(col_widths[header], len(str(value)))
    
    # Build the table
    output = []
    if title:
        output.append(f"   {title}\n")
    
    # Header row
    header_line = "   "
    separator_line = "   "
    for header in headers:
        width = col_widths[header]
        header_line += f"{header:<{width}} | "
        separator_line += "-" * width + "-+-"
    output.append(header_line.rstrip())
    output.append(separator_line.rstrip())
    
    # Data rows
    for row in rows:
        data_line = "   "
        for header, value in zip(headers, row):
            width = col_widths[header]
            data_line += f"{str(value):<{width}} | "
        output.append(data_line.rstrip())
    
    return "\n".join(output) + "\n\n"

def parse_size_to_gb(size_str):
    """Parse size string (like '8gb', '2048mb') to GB"""
    try:
        size_str = size_str.lower().strip()
        if 'gb' in size_str:
            return float(size_str.replace('gb', ''))
        elif 'mb' in size_str:
            return float(size_str.replace('mb', '')) / 1024
        elif 'kb' in size_str:
            return float(size_str.replace('kb', '')) / (1024 * 1024)
        elif 'tb' in size_str:
            return float(size_str.replace('tb', '')) * 1024
        else:
            # Try to parse as number (assume MB)
            return float(size_str) / 1024
    except:
        return 0