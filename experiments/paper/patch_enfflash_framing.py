"""Copy a pinned EnfFlash runtime and fix its stdin framing without changing strings.

The original binary/source and recorded pilots are never overwritten. Build the
returned directory with cargo, then pin the new binary hash in a new experiment.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil


FRAMING = r'''
/// Track log string literals across physical lines. A semicolon inside a
/// ToolResult string is data, even at the end of a physical line.
#[derive(Default)]
struct LogFrame {
    quoted: bool,
    escaped: bool,
}

impl LogFrame {
    fn feed(&mut self, text: &str) -> bool {
        let mut terminated = false;
        for c in text.chars() {
            if self.quoted {
                terminated = false;
                if self.escaped { self.escaped = false; }
                else if c == '\\' { self.escaped = true; }
                else if c == '"' { self.quoted = false; }
            } else if c == '"' {
                self.quoted = true;
                terminated = false;
            } else if !c.is_whitespace() {
                terminated = c == ';';
            }
        }
        terminated && !self.quoted
    }
}

#[cfg(test)]
mod framing_tests {
    use super::LogFrame;
    #[test]
    fn semicolons_and_measurement_markers_in_strings_are_data() {
        let mut f = LogFrame::default();
        assert!(!f.feed("@1 ToolResult(1, \"c\", \"user www-data;\r\n"));
        assert!(!f.feed("> measurement <\n"));
        assert!(!f.feed("worker_processes 2;\n"));
        assert!(f.feed("\");\n"));
        assert!(f.feed("@2 Tick(2);\n"));
    }
    #[test]
    fn escaped_quotes_and_backslashes_do_not_end_a_string() {
        let mut f = LogFrame::default();
        assert!(!f.feed("@1 Input(\"\\\"quoted\\\" and \\\\;\n"));
        assert!(f.feed("end\");\n"));
    }
}
'''


def prepare(source, destination):
    source, destination = Path(source), Path(destination)
    original = (source / 'src/main.rs').read_text()
    replacements = [
        ('fn main() {', FRAMING + '\nfn main() {'),
        ('let reader: Box<dyn BufRead>', 'let mut reader: Box<dyn BufRead>'),
        ('    for line in reader.lines() {',
         '    let mut framing = LogFrame::default();\n    loop {'),
        ('        let line = line.unwrap_or_else(|e| panic!("Read error: {}", e));',
         '        let mut line = String::new();\n'
         '        if reader.read_line(&mut line).unwrap_or_else(|e| panic!("Read error: {}", e)) == 0 { break; }'),
        ("        buf.push('\\n');\n        if line.trim_end().ends_with(';') {",
         '        if framing.feed(&line) {'),
    ]
    fixed = original
    for old, new in replacements:
        if fixed.count(old) != 1:
            raise ValueError('Unexpected EnfFlash source; patch needs review: ' + old)
        fixed = fixed.replace(old, new)
    original_ast = (source / 'src/ast.rs').read_text()
    old_json = '''        let args: Vec<String> = self.args.iter().map(|a| format!("{}", a)).collect();
        format!("{{ \\"name\\": \\"{}\\", \\"args\\": [ {} ] }}", self.name, args.join(", "))'''
    new_json = '''        let args: Vec<serde_json::Value> = self.args.iter().map(|a| match a {
            Value::Int(i) => serde_json::json!(i),
            Value::Float(OrderedFloat(v)) => serde_json::Value::Number(
                serde_json::Number::from_f64(*v).expect("non-finite event number")),
            Value::Str(s) => serde_json::Value::String(s.to_string()),
            Value::Bool(b) => serde_json::json!(b),
        }).collect();
        serde_json::json!({"name": self.name, "args": args}).to_string()'''
    if original_ast.count(old_json) != 1:
        raise ValueError('Unexpected EnfFlash JSON serializer; patch needs review')
    fixed_ast = original_ast.replace(old_json, new_json)
    shutil.copytree(source, destination, ignore=shutil.ignore_patterns('target', '.git'))
    (destination / 'src/main.rs').write_text(fixed)
    (destination / 'src/ast.rs').write_text(fixed_ast)
    manifest = {'patch': 'quote-aware-log-framing-and-json-v2',
                'original_main_sha256': hashlib.sha256(original.encode()).hexdigest(),
                'patched_main_sha256': hashlib.sha256(fixed.encode()).hexdigest(),
                'original_ast_sha256': hashlib.sha256(original_ast.encode()).hexdigest(),
                'patched_ast_sha256': hashlib.sha256(fixed_ast.encode()).hexdigest(),
                'preserves_line_endings': True, 'original_untouched': True}
    (destination / 'framing-patch.json').write_text(json.dumps(manifest, indent=2) + '\n')
    return manifest


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('destination', type=Path)
    args = parser.parse_args()
    print(json.dumps(prepare(args.source, args.destination), indent=2))
