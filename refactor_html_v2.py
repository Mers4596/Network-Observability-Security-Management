import os
import re

# Dosya Listesi ve Title/CSS Tanımları
files = [
    ('topology.html', 'Ağ Topolojisi | Nebula Net', 'css/pages/topology.css'),
    ('assets.html', 'Envanter ve Varlıklar | Nebula Net', 'css/pages/assets.css'),
    ('traffic.html', 'Trafik Analizi | Nebula Net', 'css/pages/traffic.css'),
    ('securityAudit.html', 'Güvenlik ve Denetim | Nebula Net', 'css/pages/security.css'),
    ('accessControl.html', 'Erişim Kontrolü | Nebula Net', 'css/pages/access.css'),
    ('alerts.html', 'Alarmlar | Nebula Net', 'css/pages/alerts.css'),
    ('settings.html', 'Sistem Ayarları | Nebula Net', 'css/pages/settings.css')
]

base_dir = r'c:\Users\Mehmet Ersolak\Desktop\Network-Observability-Security-Management\templates'

for filename, title, css_path in files:
    filepath = os.path.join(base_dir, filename)
    
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Step 1: Eğer zaten extends yapılmışsa atla
    if '{% extends "base.html" %}' in content:
        print(f"Skipping {filename}, already refactored.")
        continue

    # Step 2: Extract CSS links (optional, we already have css_path but might need extra ones like Chart.js)
    extra_scripts = ""
    if 'chart.umd.min.js' in content:
        extra_scripts += '<!-- Chart.js -->\n<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>\n'
    if 'Sortable' in content:
        extra_scripts += '<!-- SortableJS -->\n<script src="https://cdn.jsdelivr.net/npm/sortablejs@latest/Sortable.min.js"></script>\n'

    # Step 3: Extract Main Content. 
    # Genel Yapi: <!-- [SayfaAdi] İçerik --> yada <div class="[sayfaadi]-content">
    # Topbar bitişi genellikle <!-- Ana İçerik --> ile biten yerlerin altındadır. Topbar divinden sonra gelen ilk ana divi istiyoruz.
    
    # Pratik yol: '<div class="topbar-right">' u bul, onun kapandıgı divleri sayarak geç
    # Ya da daha basiti: 
    start_match = re.search(r'<div class="topbar-right">.*?</div>\s*</div>\s*(<div class="[^"]+-content">)', content, re.DOTALL)
    
    if start_match:
        content_start = start_match.start(1)
    else:
        # Fallback 1: <!-- [X] İçerik --> yorum satırını bul
        start_match = re.search(r'<!-- [^<]*?İçerik[^<]*?-->\s*(<div class="[^"]+-content">)', content)
        if start_match:
            content_start = start_match.start(1)
        else:
            print(f"FAILED to find start of content for {filename}")
            continue

    # Script tag'in basladigu yeri bul
    script_start = content.rfind('<script>')
    if script_start == -1:
        script_start = content.rfind('</body>')

    body_content = content[content_start:script_start].strip()
    
    # Remove trailing </div> that closes main-content and app-container
    body_content = re.sub(r'</div>\s*</div>\s*$', '', body_content).strip()

    # Step 4: Extract Scripts
    scripts_content = content[script_start:].replace('</body>', '').replace('</html>', '').strip()
    
    # Remove sidebar toggle script chunk since it is in base.html
    scripts_content = re.sub(r'// Sidebar daraltma/genişletme.*?\}\);', '', scripts_content, flags=re.DOTALL)
    scripts_content = re.sub(r'const sidebar = document\.getElementById.*?\}\);', '', scripts_content, flags=re.DOTALL)

    # Step 5: Format the new Jinja template
    new_template = f"""{{% extends "base.html" %}}

{{% block title %}}{title}{{% endblock %}}

{{% block extra_css %}}
<!-- Page CSS -->
<link rel="stylesheet" href="{{{{ url_for('static', filename='{css_path}') }}}}">
{extra_scripts.strip()}
{{% endblock %}}

{{% block content %}}
{body_content}
{{% endblock %}}
"""
    if scripts_content and len(scripts_content) > 15: # Daha uzun bir script kaldıysa
        new_template += f"\n{{% block scripts %}}\n{scripts_content}\n{{% endblock %}}\n"

    # Step 6: Write back
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(new_template)
    
    print(f"SUCCESS: Refactored {filename}")
