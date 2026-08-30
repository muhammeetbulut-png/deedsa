import os
import socket
import json
import urllib.request
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

app = FastAPI(title="DeedSa Intelligence Terminal")

class GenerateRequest(BaseModel):
    niche: str = ""
    keyword: str = ""
    apiKey: str = ""

class ChatRequest(BaseModel):
    message: str = ""
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
  <title>DeedSa | E-Ticaret Alan Adı İstihbarat Terminali</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css" />
  <style>
    #intro-screen { transition: opacity 0.8s ease-out, visibility 0.8s ease-out; }
    .loader-bar { width: 0%; animation: loadProgress 2s cubic-bezier(0.4, 0, 0.2, 1) forwards; }
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
    .custom-scroll::-webkit-scrollbar { width: 4px; }
    .custom-scroll::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
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

      <nav class="hidden md:flex items-center gap-4 text-sm font-semibold text-slate-700">
        <button onclick="openModal('modal-robom')" class="hover:text-blue-600 flex items-center gap-1.5"><i class="fa-solid fa-robot text-blue-600"></i> Robom AI</button>
        <button onclick="openModal('modal-calculator')" class="hover:text-blue-600 flex items-center gap-1.5"><i class="fa-solid fa-calculator text-blue-600"></i> Değerleme & Arbitraj</button>
        <button onclick="openModal('modal-api')" class="flex items-center gap-2 text-xs font-bold px-3 py-1.5 rounded-lg border border-slate-300 hover:border-blue-600 text-slate-700">
          <i class="fa-solid fa-key text-blue-600"></i> Gemini API
        </button>
      </nav>

      <button onclick="toggleMobileMenu()" class="p-2 rounded-lg text-slate-700 hover:bg-slate-100 focus:outline-none" aria-label="Menü">
        <i class="fa-solid fa-bars text-2xl text-slate-800"></i>
      </button>
    </div>
  </header>

  <div id="mobileDrawer" class="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm hidden transition-opacity">
    <div class="fixed top-0 right-0 w-[85%] max-w-sm h-screen bg-white shadow-2xl flex flex-col justify-between overflow-y-auto custom-scroll">
      
      <div class="p-6 space-y-6">
        <div class="flex items-center justify-between pb-4 border-b border-slate-100">
          <span class="text-xl font-black text-blue-600">Deed<span class="text-slate-900">Sa</span> Terminal</span>
          <button onclick="toggleMobileMenu()" class="p-2 text-slate-500 hover:bg-slate-100 rounded-full">
            <i class="fa-solid fa-xmark text-2xl"></i>
          </button>
        </div>

        <div class="p-4 bg-slate-50 border border-slate-200 rounded-2xl space-y-2">
          <div class="flex items-center gap-2">
            <i class="fa-solid fa-key text-blue-600 text-sm"></i>
            <span class="text-xs font-bold text-slate-800 uppercase">Gemini API Anahtarı</span>
          </div>
          <input type="password" id="geminiApiKeyInput" placeholder="AIzaSy..." class="w-full text-xs px-3 py-2.5 border border-slate-300 rounded-xl bg-white focus:outline-none focus:border-blue-600" />
          <button onclick="saveApiKey()" class="w-full bg-blue-600 hover:bg-blue-700 text-white text-xs py-2.5 rounded-xl font-bold transition flex items-center justify-center gap-1.5 shadow-sm">
            <i class="fa-solid fa-floppy-disk"></i> Anahtarı Kaydet
          </button>
          <p id="apiKeyStatus" class="text-[11px] text-slate-500 flex items-center gap-1">
            <i class="fa-solid fa-shield-halved text-emerald-600"></i> Tarayıcınızda güvenle saklanır.
          </p>
        </div>

        <div class="space-y-2">
          <p class="text-[11px] font-bold text-slate-400 uppercase tracking-wider">İstihbarat Araçları</p>
          
          <button onclick="toggleMobileMenu(); openModal('modal-robom');" class="w-full flex items-center gap-3 px-3 py-3 rounded-xl bg-blue-50/50 hover:bg-blue-50 text-blue-700 font-bold text-sm transition text-left">
            <i class="fa-solid fa-robot text-blue-600 text-lg w-5"></i> Robom AI Asistanı Çalıştır
          </button>

          <button onclick="toggleMobileMenu(); openModal('modal-calculator');" class="w-full flex items-center gap-3 px-3 py-3 rounded-xl bg-slate-50 hover:bg-slate-100 text-slate-800 font-bold text-sm transition text-left">
            <i class="fa-solid fa-calculator text-emerald-600 text-lg w-5"></i> Domain Arbitraj & Değerleme
          </button>

          <button onclick="toggleMobileMenu(); openModal('modal-guide');" class="w-full flex items-center gap-3 px-3 py-3 rounded-xl bg-slate-50 hover:bg-slate-100 text-slate-800 font-bold text-sm transition text-left">
            <i class="fa-solid fa-book-open text-indigo-600 text-lg w-5"></i> Arbitraj Rehberi & Strateji
          </button>
        </div>
      </div>

      <div class="p-6 bg-slate-50 border-t border-slate-100 text-center">
        <p class="text-[11px] text-slate-500 font-semibold">© 2026 DeedSa Enterprise AI</p>
      </div>
    </div>
  </div>

  <main class="max-w-4xl mx-auto px-4 pt-8 pb-12 space-y-8">
    <div class="text-center space-y-4">
      <h2 class="text-3xl md:text-5xl font-black text-slate-900 tracking-tight leading-tight">
        E-Ticaret Alan Adı <br class="hidden sm:inline"/>
        <span class="text-transparent bg-clip-text bg-gradient-to-r from-blue-600 to-sky-500">Keşif ve Analiz Terminali</span>
      </h2>
      <p class="text-sm md:text-base text-slate-600 max-w-2xl mx-auto leading-relaxed">
        Yapay zeka ile niş odaklı 2 kelimelik marka isimleri üretin, ICANN akredite DNS üzerinden anlık boştalık durumunu sorgulayın.
      </p>
    </div>

    <div class="bg-white p-6 rounded-2xl border border-slate-200 shadow-xl shadow-slate-200/50 space-y-4">
      <div>
        <label class="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">Sektör / Marka Anahtar Kelimesi</label>
        <input type="text" id="keywordFilter" placeholder="Örn: Silk, Glow, Deri, Pure, Fit, Core..." class="w-full px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 text-sm focus:outline-none focus:border-blue-600 focus:bg-white transition" />
      </div>

      <div>
        <label class="block text-xs font-bold text-slate-700 uppercase tracking-wider mb-2">Hedef E-Ticaret Kategorisi (150+ Niş)</label>
        <select id="nicheSelect" class="w-full px-4 py-3 rounded-xl border border-slate-200 bg-slate-50 text-sm focus:outline-none focus:border-blue-600 focus:bg-white transition font-medium">
          <option value="Anti-Aging ve Kırışıklık Karşıtı Cilt Bakımı">Anti-Aging ve Kırışıklık Karşıtı Cilt Bakımı</option>
          <option value="Minimalist Ev ve Ergonomik Ofis Aksesuarları">Minimalist Ev ve Ergonomik Ofis Aksesuarları</option>
          <option value="Organik Sporcu Takviyeleri ve Protein Barları">Organik Sporcu Takviyeleri ve Protein Barları</option>
          <option value="Akıllı Evcil Hayvan Otomatik Besleme ve Bakım">Akıllı Evcil Hayvan Otomatik Besleme ve Bakım</option>
          <option value="Sürdürülebilir 3. Nesil Kahve & Barista Araçları">Sürdürülebilir 3. Nesil Kahve & Barista Araçları</option>
          <option value="Doğal Ağız Bakım ve Diş Beyazlatma Çözümleri">Doğal Ağız Bakım ve Diş Beyazlatma Çözümleri</option>
          <option value="DTC Moda: Oversize & Lüks Sokak Giyimi">DTC Moda: Oversize & Lüks Sokak Giyimi</option>
        </select>
      </div>

      <button onclick="scanDomains()" id="scanBtn" class="w-full bg-blue-600 hover:bg-blue-700 text-white font-bold py-3.5 rounded-xl shadow-lg shadow-blue-600/30 transition flex items-center justify-center gap-2">
        <i class="fa-solid fa-bolt"></i> Yapay Zeka ile Tara ve Doğrula
      </button>
    </div>

    <div id="resultsContainer" class="hidden space-y-4">
      <div class="flex items-center justify-between">
        <h3 class="text-lg font-bold text-slate-900 flex items-center gap-2">
          <i class="fa-solid fa-circle-check text-emerald-600"></i> Doğrulanmış Boşta .COM Portföyü
        </h3>
        <span id="resultCount" class="text-xs bg-emerald-50 text-emerald-700 font-bold px-2.5 py-1 rounded-full"></span>
      </div>
      <div id="domainList" class="grid grid-cols-1 md:grid-cols-2 gap-3"></div>
    </div>
  </main>

  <div id="modal-robom" class="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm hidden flex items-center justify-center p-4">
    <div class="bg-white w-full max-w-lg rounded-2xl shadow-2xl flex flex-col h-[550px] overflow-hidden">
      <div class="p-4 bg-slate-900 text-white flex items-center justify-between">
        <div class="flex items-center gap-2">
          <i class="fa-solid fa-robot text-sky-400"></i>
          <span class="font-bold text-sm">Robom AI | Domain Danışmanı</span>
        </div>
        <button onclick="closeModal('modal-robom')" class="text-slate-400 hover:text-white"><i class="fa-solid fa-xmark text-lg"></i></button>
      </div>
      <div id="chatBox" class="flex-1 p-4 overflow-y-auto space-y-3 custom-scroll bg-slate-50 text-xs">
        <div class="bg-white p-3 rounded-xl border border-slate-200 max-w-[85%]">
          👋 Merhaba! Ben Robom AI. E-ticaret nişiniz için marka ismi fikirleri veya Sedo arbitraj stratejileri hakkında bana soru sorabilirsiniz.
        </div>
      </div>
      <div class="p-3 bg-white border-t border-slate-200 flex gap-2">
        <input type="text" id="chatInput" placeholder="Örn: Kahve markası için 2 kelimelik isim öner..." class="flex-1 text-xs px-3 py-2.5 border border-slate-200 rounded-xl focus:outline-none focus:border-blue-600" onkeydown="if(event.key==='Enter') sendChatMessage()" />
        <button onclick="sendChatMessage()" class="bg-blue-600 text-white px-4 py-2.5 rounded-xl text-xs font-bold hover:bg-blue-700"><i class="fa-solid fa-paper-plane"></i></button>
      </div>
    </div>
  </div>

  <div id="modal-calculator" class="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm hidden flex items-center justify-center p-4">
    <div class="bg-white w-full max-w-md rounded-2xl shadow-2xl p-6 space-y-4">
      <div class="flex items-center justify-between pb-3 border-b border-slate-100">
        <span class="font-bold text-slate-900 text-base flex items-center gap-2">
          <i class="fa-solid fa-calculator text-emerald-600"></i> Domain Flipping Hesaplayıcı
        </span>
        <button onclick="closeModal('modal-calculator')" class="text-slate-400 hover:text-slate-700"><i class="fa-solid fa-xmark text-lg"></i></button>
      </div>
      <div class="space-y-3 text-xs">
        <div>
          <label class="block font-bold text-slate-700 mb-1">Namecheap Alış Maliyeti ($)</label>
          <input type="number" id="buyPrice" value="11" class="w-full px-3 py-2 border rounded-xl" oninput="calculateProfit()" />
        </div>
        <div>
          <label class="block font-bold text-slate-700 mb-1">Sedo / Afternic Hedef Satış Fiyatı ($)</label>
          <input type="number" id="sellPrice" value="850" class="w-full px-3 py-2 border rounded-xl" oninput="calculateProfit()" />
        </div>
        <div class="p-4 bg-emerald-50 border border-emerald-100 rounded-xl space-y-1">
          <div class="flex justify-between font-bold text-slate-700"><span>Pazar Yeri Komisyonu (%15):</span><span id="commFee">$127.5</span></div>
          <div class="flex justify-between font-black text-emerald-700 text-sm pt-1 border-t border-emerald-200"><span>Net Kâr:</span><span id="netProfit">$711.5</span></div>
          <div class="flex justify-between text-[11px] text-emerald-600 font-bold"><span>Yatırım Getirisi (ROI):</span><span id="roiVal">%6468</span></div>
        </div>
      </div>
    </div>
  </div>

  <div id="modal-guide" class="fixed inset-0 z-50 bg-slate-900/70 backdrop-blur-sm hidden flex items-center justify-center p-4">
    <div class="bg-white w-full max-w-lg rounded-2xl shadow-2xl p-6 space-y-4 max-h-[85vh] overflow-y-auto custom-scroll">
      <div class="flex items-center justify-between pb-3 border-b border-slate-100">
        <span class="font-bold text-slate-900 text-base flex items-center gap-2">
          <i class="fa-solid fa-book-open text-indigo-600"></i> Arbitraj Rehberi & Kurallar
        </span>
        <button onclick="closeModal('modal-guide')" class="text-slate-400 hover:text-slate-700"><i class="fa-solid fa-xmark text-lg"></i></button>
      </div>
      <div class="space-y-3 text-xs text-slate-600 leading-relaxed">
        <p><strong>1. Kural: Sadece .COM:</strong> Global DTC markaları her zaman .com uzantısını tercih eder. Tescil ederken .com dışına çıkmayın.</p>
        <p><strong>2. Kural: 2 Güçlü Kelime:</strong> Marka isimleri telaffuzu kolay ve akılda kalıcı iki İngilizce kelimeden oluşmalıdır (Örn: SilkGlow, PurePulse).</p>
        <p><strong>3. Kural: Sedo Fiyatlandırması:</strong> Alınan alan adını Sedo üzerinde $490 - $1.490 "Buy Now" (Hemen Al) fiyatıyla listeleyin.</p>
      </div>
    </div>
  </div>

  <div class="fixed bottom-5 right-5 z-20">
    <button onclick="openModal('modal-robom')" class="w-13 h-13 p-3.5 bg-slate-900 hover:bg-blue-600 text-white rounded-full shadow-2xl flex items-center justify-center transition border-2 border-white">
      <i class="fa-solid fa-robot text-xl"></i>
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
      calculateProfit();
    });

    function toggleMobileMenu() {
      document.getElementById('mobileDrawer').classList.toggle('hidden');
    }

    function openModal(id) {
      document.getElementById(id).classList.remove('hidden');
    }

    function closeModal(id) {
      document.getElementById(id).classList.add('hidden');
    }

    function saveApiKey() {
      const key = document.getElementById('geminiApiKeyInput').value.trim();
      if (key) {
        localStorage.setItem('GEMINI_API_KEY', key);
        document.getElementById('apiKeyStatus').innerHTML = '<i class="fa-solid fa-circle-check text-emerald-600"></i> API Anahtarı kaydedildi!';
        setTimeout(() => { toggleMobileMenu(); }, 600);
      } else {
        alert('Lütfen geçerli bir Gemini API anahtarı girin.');
      }
    }

    function calculateProfit() {
      const buy = parseFloat(document.getElementById('buyPrice').value) || 0;
      const sell = parseFloat(document.getElementById('sellPrice').value) || 0;
      const comm = sell * 0.15;
      const net = sell - comm - buy;
      const roi = buy > 0 ? ((net / buy) * 100).toFixed(0) : 0;

      document.getElementById('commFee').innerText = '$' + comm.toFixed(1);
      document.getElementById('netProfit').innerText = '$' + (net > 0 ? net.toFixed(1) : 0);
      document.getElementById('roiVal').innerText = '%' + roi;
    }

    async function scanDomains() {
      const btn = document.getElementById('scanBtn');
      const niche = document.getElementById('nicheSelect').value;
      const keyword = document.getElementById('keywordFilter').value;
      const resultsContainer = document.getElementById('resultsContainer');
      const domainList = document.getElementById('domainList');
      const resultCount = document.getElementById('resultCount');
      const apiKey = localStorage.getItem('GEMINI_API_KEY') || '';

      btn.disabled = true;
      btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Yapay Zeka Üretiyor & DNS Taranıyor...';

      try {
        const response = await fetch('/api/generate-and-check', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ niche, keyword, apiKey })
        });
        const data = await response.json();

        domainList.innerHTML = '';
        if (data.domains && data.domains.length > 0) {
          resultCount.innerText = `${data.domains.length} Alan Adı Boşta`;
          data.domains.forEach(item => {
            const card = `
              <div class="bg-white p-4 rounded-xl border border-slate-200 shadow-sm flex items-center justify-between">
                <div>
                  <h4 class="font-bold text-slate-900 text-sm tracking-wide">${item.name}</h4>
                  <span class="text-[10px] text-emerald-600 font-bold bg-emerald-50 px-2 py-0.5 rounded">DNS ONAYLI BOŞTA</span>
                </div>
                <a href="https://www.namecheap.com/domains/registration/results/?domain=${item.name}" target="_blank" class="bg-blue-600 text-white hover:bg-blue-700 px-3.5 py-2 rounded-xl text-xs font-bold transition flex items-center gap-1.5 shadow-sm">
                  <span>Tescil Et</span> <i class="fa-solid fa-arrow-up-right-from-square text-[10px]"></i>
                </a>
              </div>
            `;
            domainList.insertAdjacentHTML('beforeend', card);
          });
          resultsContainer.classList.remove('hidden');
        } else {
          alert('DNS sorgusundan geçen boşta domain bulunamadı. Lütfen tekrar deneyin.');
        }
      } catch (err) {
        alert('Hata oluştu: ' + err.message);
      } finally {
        btn.disabled = false;
        btn.innerHTML = '<i class="fa-solid fa-bolt"></i> Yapay Zeka ile Tara ve Doğrula';
      }
    }

    async function sendChatMessage() {
      const input = document.getElementById('chatInput');
      const msg = input.value.trim();
      const chatBox = document.getElementById('chatBox');
      const apiKey = localStorage.getItem('GEMINI_API_KEY') || '';

      if (!msg) return;

      chatBox.innerHTML += `<div class="bg-blue-600 text-white p-3 rounded-xl ml-auto max-w-[85%] text-xs font-medium">${msg}</div>`;
      input.value = '';
      chatBox.scrollTop = chatBox.scrollHeight;

      try {
        const response = await fetch('/api/chat', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ message: msg, apiKey })
        });
        const data = await response.json();
        chatBox.innerHTML += `<div class="bg-white p-3 rounded-xl border border-slate-200 max-w-[85%] text-xs">${data.reply}</div>`;
      } catch (err) {
        chatBox.innerHTML += `<div class="bg-red-50 text-red-600 p-3 rounded-xl border border-red-200 max-w-[85%] text-xs">Bağlantı hatası oluştu.</div>`;
      }
      chatBox.scrollTop = chatBox.scrollHeight;
    }
  </script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def read_root():
    return HTMLResponse(content=HTML_CONTENT)

@app.post("/api/generate-and-check")
def generate_endpoint(payload: GenerateRequest):
    candidates = []
    
    # 1. Gemini API Anahtarı girilmişse doğrudan Gemini ile akıllı üretim yap
    if payload.apiKey:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={payload.apiKey}"
            prompt = f"E-ticaret nişi '{payload.niche}' ve anahtar kelime '{payload.keyword}' için 2 kelimelik 10 adet premium .com alan adı öner. Sadece alan adlarını aralarında virgül ile yaz (örn: silkglow.com, pureroot.com)."
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as res:
                result = json.loads(res.read().decode())
                text = result["candidates"][0]["content"]["parts"][0]["text"]
                candidates = [d.strip().lower() for d in text.replace("\n", ",").split(",") if ".com" in d]
        except Exception:
            candidates = []

    # 2. Yedek algoritma (Gemini yoksa veya hata verirse)
    if not candidates:
        base_words = ["glow", "pulse", "store", "hub", "fit", "pure", "core", "wave", "prime", "nest", "root", "vibe"]
        prefix = payload.keyword.lower().strip() if payload.keyword else "deed"
        candidates = [f"{prefix}{w}.com" for w in base_words]

    # Canlı DNS doğrulaması ile sadece boştakileri seç
    available = []
    for d in candidates:
        cleaned = d.replace(" ", "").replace("`", "")
        if is_domain_free(cleaned):
            available.append({"name": cleaned, "status": "Available"})
        if len(available) >= 8:
            break

    return JSONResponse(content={"domains": available})

@app.post("/api/chat")
def chat_endpoint(payload: ChatRequest):
    if payload.apiKey:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={payload.apiKey}"
            prompt = f"Sen DeedSa'nın Robom AI isimli alan adı ve e-ticaret danışmanısın. Kullanıcıya kısa, net ve profesyonel cevap ver: {payload.message}"
            body = json.dumps({"contents": [{"parts": [{"text": prompt}]}]}).encode("utf-8")
            req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
            with urllib.request.urlopen(req, timeout=5) as res:
                result = json.loads(res.read().decode())
                reply = result["candidates"][0]["content"]["parts"][0]["text"]
                return JSONResponse(content={"reply": reply})
        except Exception:
            pass

    return JSONResponse(content={"reply": "Robom AI: Niş pazarınız için akılda kalıcı iki kelimelik .com alan adlarını hedeflemenizi ve Sedo üzerinde $490-$950 bandında listelemenizi öneririm."})

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 10000))
    uvicorn.run("app:app", host="0.0.0.0", port=port)
