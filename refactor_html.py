import os
import re

def refactor_html(filepath, block_title, extra_css_path):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # Regex ile sayfanın asıl body içeriğini çekelim (main-content -> dashboard-content benzeri)
    # Veya direkt "class="main-content"" içindeki kısmın altını alalım.
    
    # Template özgü div'i bulmaya çalışalım. Genelde topbar'dan sonra gelir.
    # Örnek: <div class="topology-content">
    content_match = re.search(r'<div class="[^"]+-content"[^>]*>(.*)</div>\s*</div>\s*</div>', content, re.DOTALL)
    
    # Eğer div content şeklinde bulamadıysa, topbar bitimini arayalım
    if not content_match:
        # Son div bitimine kadar al (scripts hariç)
        # Bazen sayfa isimleri değişiyor, o yüzden "topbar" bitiminden script etiketine kadar olan kısmı da alabiliriz.
        topbar_end = content.find('<!-- Topbar -->')
        if topbar_end == -1:
            topbar_end = content.find('<div class="topbar">')
            
        if topbar_end != -1:
            # Topbar divinin kapanışını bulalım (yaklaşık olarak)
            # Bu biraz karmaşık, onun yerine manuel veya HTML parser kullanmak daha iyi.
            pass

    # Daha iyi bir yöntem: Beautiful Soup kullanmak veya sadece bilinen yapıları regex ile değiştirmek.
    # Burada sunucuda çalıştırdığımız için standart kütüphaneleri kullanmalıyız. Python'un html parser'ı var ama regex şablonları da işler.
    
    # HTML'in başını atalım, <!-- Ana İçerik --> altındaki asıl içeriği (dashboard-content veya türevi) blok içine alalım.
    
    # Hedefimiz sadece <style> bloklarını silmek (zaten sildik).
    # Şimdi <html>, <head>, <script> vs silip base.html yapısı kurmak.
    p = re.compile(r'.*?<!-- Ana İçerik -->.*?<div class="topbar-right">.*?</div>\s*</div>\s*</div>\s*(<div class="[^"]+-content">.*)</div>\s*</div>\s*</div>(.*)', re.DOTALL)
    
    # Birçok html sayfası aynı yapıda.
    m = p.search(content)
    if m:
        main_html = m.group(1).strip()
        scripts_html = m.group(2).strip()
        
        # Scriptleri temize çekelim (</body> </html> kısımlarını kaldır)
        scripts_html = re.sub(r'</body>\s*</html>', '', scripts_html).strip()
        
        # Sadece ilgili sayfaya ait js kısımlarını bırak, mesela sidebar js varsa uçur.
        scripts_html = re.sub(r'// Sidebar daraltma/genişletme.*?\}\);', '', scripts_html, flags=re.DOTALL)
        scripts_html = re.sub(r'const sidebar = document\.getElementById.*?\}\);', '', scripts_html, flags=re.DOTALL)

        new_content = f"""{{% extends "base.html" %}}

{{% block title %}}{block_title}{{% endblock %}}

{{% block extra_css %}}
<link rel="stylesheet" href="{{{{ url_for('static', filename='{extra_css_path}') }}}}">
{{% endblock %}}

{{% block content %}}
{main_html}
{{% endblock %}}
"""
        if scripts_html:
            # Eğer window.onload içeriyorsa veya sadece script varsa body'si yeterli
            new_content += f"\n{{% block scripts %}}\n{scripts_html}\n{{% endblock %}}\n"

        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"Refactored {os.path.basename(filepath)}")
    else:
        # regex işlemezse 2. bir deneme (topology'de sidebar yapısı farklı olabilir vb)
        print(f"Failed to match regex for {os.path.basename(filepath)}")
        
        # Manuel arama:
        try:
            start_idx = content.find('<!-- Topbar -->')
            if start_idx != -1:
                # Topbar'ın bitiş div'ini bul
                # "</div>" sayalım
                divs = 1
                curr = content.find('<div', start_idx + 1)
                curr_close = content.find('</div>', start_idx + 1)
                
                search_idx = start_idx + 20
                while divs > 0 and search_idx < len(content):
                    next_div = content.find('<div', search_idx)
                    next_close = content.find('</div>', search_idx)
                    
                    if next_div != -1 and next_div < next_close:
                        divs += 1
                        search_idx = next_div + 4
                    elif next_close != -1:
                        divs -= 1
                        search_idx = next_close + 6
                        if divs == 0:
                            break
                    else:
                        break
                        
                topbar_end_idx = search_idx
                
                # İçerik div'inin başı
                content_start = content.find('<div class="', topbar_end_idx)
                
                # Script başı
                script_start = content.find('<script>', content_start)
                if script_start == -1:
                    # Belki dışarıdan script yüklenmiştir
                    script_start = content.find('</body>', content_start)
                
                main_html = content[content_start:script_start].strip()
                # En sondaki </div></div> fazlalıklarını at
                main_html = re.sub(r'</div>\s*</div>\s*$', '', main_html).strip()
                
                scripts_html = content[script_start:].replace('</body>', '').replace('</html>', '').strip()
                
                # Sidebar js temizliği
                scripts_html = re.sub(r'// Sidebar daraltma/genişletme.*?\}\);', '', scripts_html, flags=re.DOTALL)
                
                new_content = f"""{{% extends "base.html" %}}

{{% block title %}}{block_title}{{% endblock %}}

{{% block extra_css %}}
<link rel="stylesheet" href="{{{{ url_for('static', filename='{extra_css_path}') }}}}">
{{% endblock %}}

{{% block content %}}
{main_html}
{{% endblock %}}
"""
                if scripts_html:
                    new_content += f"\n{{% block scripts %}}\n{scripts_html}\n{{% endblock %}}\n"

                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(new_content)
                print(f"Refactored fallback for {os.path.basename(filepath)}")
                
        except Exception as e:
            print(f"Fallback failed too: {e}")

if __name__ == '__main__':
    base = r'c:\\Users\\Mehmet Ersolak\\Desktop\\Network-Observability-Security-Management\\templates'
    
    files = [
        ('topology.html', 'Ağ Topolojisi | Nebula Net', 'css/pages/topology.css'),
        ('assets.html', 'Envanter ve Varlıklar | Nebula Net', 'css/pages/assets.css'),
        ('traffic.html', 'Trafik Analizi | Nebula Net', 'css/pages/traffic.css'),
        ('securityAudit.html', 'Güvenlik ve Denetim | Nebula Net', 'css/pages/security.css'),
        ('accessControl.html', 'Erişim Kontrolü | Nebula Net', 'css/pages/access.css'),
        ('alerts.html', 'Alarmlar | Nebula Net', 'css/pages/alerts.css'),
        ('settings.html', 'Sistem Ayarları | Nebula Net', 'css/pages/settings.css')
    ]
    
    for f, title, css in files:
        refactor_html(os.path.join(base, f), title, css)
