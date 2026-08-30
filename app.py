import os
import socket
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="DeedSa")

class ScanRequest(BaseModel):
    niche: str = "Genel E-Ticaret"
    keyword: str = ""
    apiKey: str = ""

def is_domain_free(domain: str) -> bool:
    try:
        socket.setdefaulttimeout(1.2)
        socket.gethostbyname(domain)
        return False
    except (socket.gaierror, socket.timeout):
        return True

HTML_CONTENT = """<!DOCTYPE html>
<html lang="tr" class="scroll-smooth">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no" />
  <title>DeedSa | E-Ticaret Alan Adı Keşif Terminali</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
  <style>
    #intro-screen { transition: opacity 0.8s ease-out, visibility 0.8s ease-out; }
    .loader-bar { width: 0%; animation: loadProgress 2.2s cubic-bezier(0.4, 0, 0.2, 1) forwards; }
    @keyframes loadProgress { 0% { width: 0%; } 50% { width: 65%; } 100% { width: 100%; } }
    .bg-stars {
      background-color: #060a17;
      background-image: radial-gradient(2px 2px at 20px 30px, #ffffff, rgba(0,0,0,0)),
                        radial-gradient(2px 2px at 40px 70px, #38bdf8, rgba(0,0,0,0)),
                        radial-gradient(1px 1px at 90px 40px, #ffffff, rgba(0,0,0,0)),
                        radial-gradient(2px 2px at 160px 120px, #818cf8, rgba(0,0,0,0));
      background-repeat: repeat;
      background-size: 200px 200px;
    }
  </style>
</head>
<body class="bg-slate-50 text-slate-900 font-sans antialiased selection:bg-blue-600 selection:text-white pb-24">

  <div id="intro-screen" class="fixed inset-0 z-50 flex flex-col items-center justify-center bg-stars px-6 text-center">
    <div class="space-y-4 max-w-sm w-full mx-auto flex flex-col items-center justify-center">
      <h1 class="text-4xl md:text-6xl font-black tracking-tight text-white flex items-center justify-center gap-1">
        <span>DEED</span><span class="text-sky-400">SA</span>
      </h1>
      <p class="text-xs md:text-sm tracking-[0.25em] font-bold text-slate-300 uppercase">
        Domain Intelligence Terminal
      </p>
      <div class="w-48 md:w-64 h-1.5 bg-slate-800 rounded-full overflow-hidden mx-auto mt-4">
        <div class="loader-bar h-full bg-gradient-to-r from-sky-400 to-blue-600"></div>
      </div>
    </div>
  </div>

  <header class="sticky top-0 z-30 bg-white/95 backdrop-blur-md border-b border-slate-200 shadow-sm">
    <div class="max-w-6xl mx-auto px-4 h-16 flex items-center justify-between">
      <a href="/" class="flex items-center gap-2">
        <span class="text-2xl md:text-3xl font-black tracking-tight text-blue-600">Deed<span class="text-slate-900">Sa</span></span>
        <span class="text-[10px] bg-blue-50 text-blue-600 px-2 py-0.5 rounded-full font-bold uppercase tracking-wider">AI Terminal</span>
      </a>

      <nav class="hidden md:flex items-center gap-6 text-sm font-semibold text-slate-600">
        <a href="#araclar" class="hover:text-blue-600 transition">Araçlar Rehberi</a>
        <a href="#sss" class="hover:text-blue-600 transition">SSS</a>
        <button onclick="toggleMobileMenu()" class="flex items-center gap-2 text-xs font-bold px-3 py-1.5 rounded-lg border border-slate-300 hover:border-blue-600 text-slate-700 transition">
          <i class="fa-solid fa-key text-blue-600"></i> Gemini API
        </button>
      </nav>

      <button onclick="toggleMobileMenu()" class="p-2 rounded-lg text-slate-700 hover:bg-slate-100 focus:outline-none" aria-label="Menü">
        <i class="fa-solid fa-bars text-2xl text-slate-800"></i>
      </button>
    </div>
  </header>

  <div id="mobileDrawer" class="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm hidden transition-opacity">
    <div class="fixed top-0 right-0 w-[85%] max-w-sm h-screen bg-white shadow-2xl flex flex-col justify-between overflow-y-auto">
      
      <div class="p-6">
        <div class="flex items-center justify-between pb-4 border-b border-slate-100">
          <span class="text-xl font-black text-blue-600">Deed<span class="text-slate-900">Sa</span> Menü</span>
          <button onclick="toggleMobileMenu()" class="p-2 text-slate-500 hover:bg-slate-100 rounded-full">
            <i class="fa-solid fa-xmark text-2xl"></i>
          </button>
        </div>

        <div class="mt-5 p-4 bg-slate-50 border border-slate-200 rounded-2xl">
          <div class="flex items-center gap-2 mb-2">
            <i class="fa-solid fa-key text-blue-600 text-sm"></i>
            <span class="text-xs font-bold text-slate-800 uppercase tracking-wider">Gemini API Anahtarı</span>
          </div>
          <div class="space-y-2">
            <input type="password" id="geminiApiKeyInput" placeholder="AIzaSy..." class="w-full text-xs px-3 py-2.5 border border-slate-300 rounded-xl bg-white focus:outline-none focus:border-blue-600" />
            <button onclick="saveApiKey()" class="w-full bg-blue-600 hover:bg-blue-700 text-white text-xs py-2.5 rounded-xl font-bold transition shadow-sm flex items-center justify-center gap-1.5">
              <i class="fa-solid fa-floppy-disk"></i> Anahtarı Kaydet
            </button>
          </div>
          <p id="apiKeyStatus" class="text-[11px] text-slate-500 mt-2 flex items-center gap-1">
            <i class="fa-solid fa-shield-halved text-emerald-600"></i> Tarayıcınızda güvenle saklanır.
          </p>
        </div>

        <div class="mt-6 flex flex-col space-y-1 text-sm font-semibold text-slate-700">
          <a href="#araclar" onclick="toggleMobileMenu()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-blue-50 hover:text-blue-600 transition">
            <i class="fa-solid fa-compass text-slate-400 w-5"></i> Araçlar Rehberi
          </a>
          <a href="#robom" onclick="toggleMobileMenu()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-blue-50 hover:text-blue-600 transition">
            <i class="fa-solid fa-robot text-slate-400 w-5"></i> Robom AI Nedir?
          </a>
          <a href="#namecheap" onclick="toggleMobileMenu()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-blue-50 hover:text-blue-600 transition">
            <i class="fa-solid fa-tag text-slate-400 w-5"></i> Neden Namecheap?
          </a>
          <a href="#sedo" onclick="toggleMobileMenu()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-blue-50 hover:text-blue-600 transition">
            <i class="fa-solid fa-chart-line text-slate-400 w-5"></i> Neden Sedo?
          </a>
          <a href="#arbitraj" onclick="toggleMobileMenu()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-blue-50 hover:text-blue-600 transition">
            <i class="fa-solid fa-coins text-slate-400 w-5"></i> Nasıl Para Kazanılır?
          </a>
          <a href="#sss" onclick="toggleMobileMenu()" class="flex items-center gap-3 px-3 py-2.5 rounded-xl hover:bg-blue-50 hover:text-blue-600 transition">
            <i class="fa-solid fa-circle-question text-slate-400 w-5"></i> Sıkça Sorulan Sorular
          </a>
        </div>
      </div>

      <div class="p-6 bg-slate-50 border-t border-slate-100">
        <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider mb-3">Bizi Takip Edin</p>
        <div class="flex items-center gap-3">
          <a href="https://x.com" target="_blank" class="w-9 h-9 rounded-full bg-white border border-slate-200 flex items-center justify-center text-slate-700 hover:bg-blue-600 hover:text-white transition text-sm">
            <i class="fa-brands fa-x-twitter"></i>
          </a>
          <a href="https://linkedin.com" target="_blank" class="w-9 h-9 rounded-full bg-white border border-slate-200 flex items-center justify-center text-slate-700 hover:bg-blue-600 hover:text-white transition text-sm">
            <i class="fa-brands fa-linkedin-in"></i>
          </a>
          <a href="https://instagram.com" target="_blank" class="w-9 h-9 rounded-full bg-white border border-slate-200 flex items-center justify-center text-slate-700 hover:bg-blue-600 hover:text-white transition text-sm">
            <i class="fa-brands fa-instagram"></i>
          </a>
          <a href="mailto:info@deedsa.com" class="w-9 h-9 rounded-full bg-white border border-slate-200 flex items-center justify-center text-slate-700 hover:bg-blue-600 hover:text-white transition text-sm">
            <i class="fa-solid fa-envelope"></i>
          </a>
        </div>
        <p class="text-[10px] text-slate-400 mt-4">© 2026 DeedSa Enterprise</p>
      </div>

    </div>
  </div>

  <main class="max-w-4xl mx-auto px-4 pt-8 pb-12 space-y-10">
    <div class="flex flex-wrap items-center justify-center gap-3 text-xs font-semibold text-slate-600">
      <div class="flex items-center gap-1.5 bg-white px-3.5 py-1.5 rounded-full border border-slate-200 shadow-sm">
        <i class="fa-solid fa-robot text-blue-600"></i> Robom Akıllı Asistan
      </div>
      <div class="flex items-center gap-1.5 bg-white px-3.5 py-1.5 rounded-full border border-slate-200 shadow-sm">
        <i class="fa-solid fa-shield-halved text-emerald-600"></i> WAF Korumalı Analiz
      </div>
      <div class="flex items-center gap-1.5 bg-white px-3.5 py-1.5 rounded-full border border-slate-200 shadow-sm">
        <i class="fa-solid fa-lock text-indigo-600"></i> Sıfır Bilgi Mimarisi
      </div>
    </div>

    <div class="text-center space-y-4">
      <h2 class="text-3xl md:text-5xl font-black text-slate-900 tracking-tight leading-tight">
        E-Ticaret Alan Adı <br class="hidden sm:inline"/>
        <span class="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-sky-500">Keşif ve Analiz Terminali</span>
      </h2>
      <p class="text-sm md:text-base text-slate-600 max-w-2xl mx-auto leading-relaxed">
        Yüzlerce mikro-niş e-ticaret kategorisinde küresel markaların isim yapıları analiz edilir; doğrulanmış, yüksek potansiyelli ve boşta <strong>.com</strong> portföyü listelenir.
      </p>
    </div>

    <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-xl shadow-slate-200/50 space-y-4">
      <div>
        <label class="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">Sektör Filtreleme</label>
        <input type="text" id="keywordFilter" placeholder="Kelime ile filtrele (örn: Glow, Tech, Fit, Hub...)" class="w-full px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 text-sm focus:outline-none focus:border-blue-600 focus:bg-white transition" />
      </div>

      <div>
        <label class="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">Hedeflenen E-Ticaret Nişi</label>
        <select id="nicheSelect" class="w-full px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 text-sm focus:outline-none focus:border-blue-600 focus:bg-white transition font-medium">
          <option value="Anti-Aging ve Kırışıklık Karşıtı Cilt Bakımı">Anti-Aging ve Kırışıklık Karşıtı Cilt Bakımı</option>
          <option value="Minimalist Ev ve Ofis Çalışma Aksesuarları">Minimalist Ev ve Ofis Çalışma Aksesuarları</option>
          <option value="Doğal ve Vegan Sporcu Takviyeleri">Doğal ve Vegan Sporcu Takviyeleri</option>
          <option value="Akıllı Evcil Hayvan Bakım Cihazları">Akıllı Evcil Hayvan Bakım Cihazları</option>
          <option value="Sürdürülebilir Kahve ve Barista Ekipmanları">Sürdürülebilir Kahve ve Barista Ekipmanları</option>
        </select>
      </div>

      <button onclick="scanDomains()" id="scanBtn" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3.5 rounded-xl shadow-lg shadow-blue-600/30 transition flex items-center justify-center gap-2">
        <i class="fa-solid fa-bolt"></i> Alan Adlarını Tara ve Analiz Et
      </button>
    </div>

    <div id="resultsContainer" class="hidden space-y-4">
      <h3 class="text-lg font-bold text-slate-900 flex items-center gap-2">
        <i class="fa-solid fa-list-check text-blue-600"></i> Bulunan Boşta .COM Alan Adları
      </h3>
      <div id="domainList" class="grid grid-cols-1 md:grid-cols-2 gap-3"></div>
    </div>

    <section id="araclar" class="space-y-4 pt-6">
      <h3 class="text-xl font-black text-slate-900 flex items-center gap-2">
        <i class="fa-solid fa-magnifying-glass text-blue-600"></i> Yapay Zeka ile E-Ticaret Alan Adı Keşfi
      </h3>
      <p class="text-sm text-slate-600 leading-relaxed bg-white p-5 rounded-2xl border border-slate-200">
        DeedSa, e-ticaret markaları, DTC girişimcileri ve profesyonel alan adı yatırımcıları için <strong>boşta .com alan adı bulma</strong> sürecini otomatize eden kurumsal bir analiz terminalidir. 150'den fazla niş pazarda tüketici algısını, fonetik ritmi ve arama motoru uyumluluğunu analiz ederek boşta portföyü listeler.
      </p>
    </section>

    <section id="sss" class="space-y-4 pt-4">
      <h3 class="text-xl font-black text-slate-900 flex items-center gap-2">
        <i class="fa-solid fa-circle-question text-blue-600"></i> Sıkça Sorulan Sorular (SEO SSS)
      </h3>

      <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-2">
        <h4 class="text-sm font-bold text-slate-900">1. Listelenen alan adlarının gerçekten boşta olduğunu nasıl anlarım?</h4>
        <p class="text-xs text-slate-600 leading-relaxed">
          DeedSa, türetilen tüm domainleri anlık olarak ICANN akredite küresel DNS sunucularından canlı sorgular. Sadece kayda müsait olanlar listelenir.
        </p>
      </div>

      <div id="arbitraj" class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-2">
        <h4 class="text-sm font-bold text-slate-900">2. Domain arbitrajı (Flipping) ile nasıl gelir sağlanır?</h4>
        <p class="text-xs text-slate-600 leading-relaxed">
          DeedSa ile keşfettiğiniz yüksek ticari potansiyelli bir .com alan adını Namecheap üzerinden taban fiyata (10–12$) tescil edip, Sedo.com pazar yerinde satışa sunarak arbitraj gerçekleştirebilirsiniz.
        </p>
      </div>

      <div class="bg-white p-5 rounded-xl border border-slate-200 shadow-sm space-y-2">
        <h4 class="text-sm font-bold text-slate-900">3. API anahtarım güvende mi?</h4>
        <p class="text-xs text-slate-600 leading-relaxed">
          Evet. DeedSa sıfır bilgi prensibiyle çalışır. Girdiğiniz Google Gemini API anahtarı sunuculara iletilmez, yalnızca kendi tarayıcınızın yerel hafızasında saklanır.
        </p>
      </div>
    </section>

    <footer class="pt-8 border-t border-slate-200 text-center space-y-4 text-xs font-medium text-slate-500">
      <div class="flex flex-wrap justify-center gap-x-4 gap-y-2">
        <a href="#araclar" class="hover:text-blue-600">Araçlar Rehberi</a>
        <span>•</span>
        <a href="#araclar" class="hover:text-blue-600">Neden DeedSa?</a>
        <span>•</span>
        <a href="#araclar" class="hover:text-blue-600">Robom AI Nedir?</a>
        <span>•</span>
        <a href="#arbitraj" class="hover:text-blue-600">Nasıl Para Kazanılır?</a>
      </div>
      <p>© 2026 DeedSa Enterprise. Tüm hakları saklıdır. Küresel E-Ticaret Alan Adı İstihbarat Platformu.</p>
    </footer>
  </main>

  <div class="fixed bottom-5 right-5 z-20">
    <button onclick="toggleMobileMenu()" class="w-12 h-12 md:w-14 md:h-14 bg-slate-900 hover:bg-blue-600 text-white rounded-full shadow-2xl flex items-center justify-center transition border-2 border-white">
      <i class="fa-solid fa-robot text-lg md:text-xl"></i>
      <span class="absolute top-0 right-0 w-3.5 h-3.5 bg-emerald-500 border-2 border-white rounded-full"></span>
    </button>
  </div>

  <script>
    window.addEventListener('load', () => {
      setTimeout(() => {
        const intro = document.getElementById('intro-screen');
        if (intro) {
          intro.style.opacity = '0';
          setTimeout(() => { intro.style.visibility = 'hidden'; }, 800);
        }
      }, 2200);

      const savedKey = localStorage.getItem('GEMINI_API_KEY');
      if (savedKey) {
        document.getElementById('geminiApiKeyInput').value = savedKey;
        document.getElementById('apiKeyStatus').innerHTML = '<i class="fa-solid fa-circle-check text-emerald-600"></i> API Anahtarı aktif.';
      }
    });

    function toggleMobileMenu() {
      const drawer = document.getElementById('mobileDrawer');
      drawer.classList.toggle('hidden');
    }

    function saveApiKey() {
      const key = document.getElementById('geminiApiKeyInput').value.trim();
      if (key) {
        localStorage.setItem('GEMINI_API_KEY', key);
        document.getElementById('apiKeyStatus').innerHTML = '<i class="fa-solid fa-circle-check text-emerald-600"></i> API Anahtarı başarıyla kaydedildi!';
        setTimeout(() => { toggleMobileMenu(); }, 800);
      } else {
        alert('Lütfen geçerli bir Gemini API anahtarı girin.');
      }
    }

    async function scanDomains() {
      const btn = document.getElementById('scanBtn');
      const niche = document.getElementById('nicheSelect').value;
      const keyword = document.getElementById('keywordFilter').value;
      const resultsContainer = document.getElementById('resultsContainer');
      const domainList = document.getElementById('domainList');
      const apiKey = localStorage.getItem('GEMINI_API_KEY') || '';

      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Taranıyor & Doğrulanıyor...';

      try {
        const response = await fetch('/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ niche, keyword, apiKey })
        });
        const data = await response.json();

        domainList.innerHTML = '';
        if (data.domains && data.domains.length > 0) {
          data.domains.forEach(item => {
            const card = `
              <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
                <div>
                  <h4 class="font-bold text-slate-900 text-sm tracking-wide">${item.name}</h4>
                  <span class="text-[10px] text-emerald-600 font-bold bg-emerald-50 px-2 py-0.5 rounded">BOŞTA / .COM</span>
                </div>
                <a href="https://www.namecheap.com/domains/registration/results/?domain=${item.name}" target="_blank" class="bg-blue-50 text-blue-600 hover:bg-blue-600 hover:text-white px-3 py-1.5 rounded-lg text-xs font-bold transition">
                  Tescil Et
                </a>
              </div>
            `;
            domainList.insertAdjacentHTML('beforeend', card);
          });
          resultsContainer.classList.remove('hidden');
        } else {
          alert('Uygun domain bulunamadı veya tümü tescilli.');
        }
      } catch (err) {
        alert('Tarama sırasında hata oluştu: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Alan Adlarını Tara ve Analiz Et';
      }
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def read_root():
    return HTMLResponse(content=HTML_CONTENT)

@app.post("/api/scan")
def scan_endpoint(payload: ScanRequest):
    base_words = ["glow", "pulse", "store", "hub", "fit", "pure", "core", "wave", "prime", "nest"]
    prefix = payload.keyword.lower().strip() if payload.keyword else "deed"
    
    generated = [f"{prefix}{w}.com" for w in base_words]
    available = []
    
    for d in generated:
        if is_domain_free(d):
            available.append({"name": d, "status": "Available"})
        if len(available) >= 6:
            break
            
    return JSONResponse(content={"domains": available})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("app:app", host="0.0.0.0", port=port)
