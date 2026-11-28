//! HTML export: a self-contained page (no scripts, no external files) for reading or sharing.

use crate::finding::Severity;
use crate::report::{Report, VerdictLevel};

fn esc(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;").replace('"', "&quot;")
}

impl Report {
    pub fn to_html(&self) -> String {
        self.shown().write_html()
    }

    fn write_html(&self) -> String {
        let v = self.verdict();
        let col = match v.level {
            VerdictLevel::Clean => "#4cb86b",
            VerdictLevel::Minor => "#4a9ad4",
            VerdictLevel::Attention => "#f07a3a",
            VerdictLevel::Alarm => "#e03e52",
        };
        let mut o = String::new();
        o.push_str(
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>Scanner report</title><style>\
body{font:15px/1.5 system-ui,sans-serif;background:#12161c;color:#dce3ea;padding:24px;max-width:960px;margin:auto}\
h1{margin:0 0 4px}.muted{color:#8b98a8}.verdict{border:1px solid;border-radius:8px;padding:12px 16px;margin:16px 0}\
.f{background:#202731;border-left:5px solid;border-radius:6px;padding:10px 14px;margin:10px 0}\
.f h3{margin:2px 0 6px}.tag{font-size:11px;font-weight:bold;color:#000;border-radius:4px;padding:1px 7px}\
pre{background:#12161c;padding:8px;border-radius:4px;overflow:auto;font-size:13px}.cmd{color:#3da58a}\
</style></head><body>",
        );
        o.push_str(&format!(
            "<h1>Scanner – intrusion and backdoor report</h1><div class=\"muted\">{} · {} · kernel {} · {} · root: {}</div>",
            esc(&self.hostname),
            esc(&self.os),
            esc(&self.kernel),
            esc(&self.generated_at),
            if self.running_as_root { "yes" } else { "no" }
        ));
        o.push_str(&format!(
            "<div class=\"verdict\" style=\"border-color:{col};background:{col}22\"><b>{}</b><br>{}</div>",
            esc(&v.headline),
            esc(&v.detail)
        ));
        let s = &self.summary;
        o.push_str(&format!("<p>{} critical · {} high · {} medium · {} low · {} info ({} total)</p>", s.critical, s.high, s.medium, s.low, s.info, s.total));
        for f in &self.findings {
            let c = match f.severity {
                Severity::Critical => "#e03e52",
                Severity::High => "#f07a3a",
                Severity::Medium => "#e4c03c",
                Severity::Low => "#4a9ad4",
                Severity::Info => "#8b98a8",
            };
            o.push_str(&format!(
                "<div class=\"f\" style=\"border-color:{c}\"><span class=\"tag\" style=\"background:{c}\">{}</span> <span class=\"muted\">{} · {}</span><h3>{}</h3>",
                f.severity.label().to_uppercase(),
                esc(&f.module),
                esc(&format!("{}{}", f.rule, if f.user_level { " · user level" } else { "" })),
                esc(&f.title)
            ));
            if !f.description.is_empty() {
                o.push_str(&format!("<p>{}</p>", esc(&f.description)));
            }
            if !f.evidence.is_empty() {
                o.push_str(&format!("<b>Evidence</b><pre>{}</pre>", esc(&f.evidence)));
            }
            if !f.verify.is_empty() {
                o.push_str("<b>Check it yourself</b><pre class=\"cmd\">");
                for cmd in &f.verify {
                    o.push_str(&format!("$ {}\n", esc(cmd)));
                }
                o.push_str("</pre>");
            }
            o.push_str("</div>");
        }
        if !self.notes.is_empty() {
            o.push_str("<h2>Notes</h2><ul>");
            for n in &self.notes {
                o.push_str(&format!("<li>{}</li>", esc(n)));
            }
            o.push_str("</ul>");
        }
        o.push_str("<p class=\"muted\">The scanner changes nothing on the system. Every action is done manually after verification.</p></body></html>");
        o
    }
}
