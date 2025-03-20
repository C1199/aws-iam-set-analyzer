from jinja2 import Environment, PackageLoader, select_autoescape

env = Environment(
    loader=PackageLoader("set_analyzer"),
    autoescape=select_autoescape()
)

def render_template(policy_json, report_table):
    template = env.get_template("template.html")
    report = template.render(policy_json=policy_json, report_table=report_table)
    with open("report.html", "w") as writer:
        writer.write(report)
    return