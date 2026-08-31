import os
import re
import json
import time
import asyncio
from collections import defaultdict
import dns.asyncresolver
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse
from pydantic import BaseModel, Field
from typing import List
import httpx

app = FastAPI(
    title="DeedSa Enterprise Domain Intelligence",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -------------------------------------------------------------
# 1. GÜVENLİK DUVARI (WAF)
# -------------------------------------------------------------
REQUEST_HISTORY = defaultdict(list)
USER_STRIKES = defaultdict(int)
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 60
COOLDOWN_SECONDS = 1

TOXIC_PATTERNS = [
    r"\b(küfür|argo|amk|aq|oç|orospu|piç|siktir|yarrak|yarak|göt|meme|porn|sik|taşak|aptal|salak|gerizekalı|fuck|bitch|asshole|dick|pussy|shit)\b",
    r"(.)\1{5,}",
]

def check_toxic_or_absurd(text: str) -> bool:
    clean_t = text.lower().strip()
    if len(clean_t) < 2:
        return True
    for pat in TOXIC_PATTERNS:
        if re.search(pat, clean_t):
            return True
    return False

@app.middleware("http")
async def security_firewall_middleware(request: Request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self' https: data:; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' https://generativelanguage.googleapis.com;"
    )
    return response

# -------------------------------------------------------------
# 2. ARAYÜZ VE HTML İÇERİĞİ
# -------------------------------------------------------------
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="tr" prefix="og: https://ogp.me/ns#">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    
    <!-- IMPACT NAMECHEAP DOĞRULAMA KODU -->
    <meta name="impact-site-verification" content="cae4c162-7add-4579-9b9f-e8a54f39b299">
    
    <!-- GELİŞMİŞ SEO VE META ETİKETLERİ -->
    <title>DeedSa | E-Ticaret Boşta .COM Alan Adı İstihbarat ve Analiz Terminali</title>
    <meta name="description" content="Yüzlerce e-ticaret kategorisinde yapay zeka ile 2 kelimelik boşta .com domainleri keşfedin. Canlı DNS/RDAP sorgulama, sosyal medya radarı ve Sedo/Namecheap arbitraj analizi.">
    <meta name="keywords" content="e-ticaret domain bulucu, boşta com alan adları, yapay zeka alan adı türetme, domain arbitrajı, sedo domain satışı, namecheap domain alma, e-ticaret marka isimleri">
    <meta name="robots" content="index, follow, max-snippet:-1, max-image-preview:large, max-video-preview:-1">
    <meta name="author" content="DeedSa Enterprise">
    <meta name="theme-color" content="#0284c7">
    <meta name="application-name" content="DeedSa">
    <link rel="canonical" href="https://deedsa.com/">

    <!-- OPEN GRAPH -->
    <meta property="og:locale" content="tr_TR">
    <meta property="og:type" content="website">
    <meta property="og:site_name" content="DeedSa Terminal">
    <meta property="og:title" content="DeedSa | E-Ticaret Boşta .COM Alan Adı İstihbarat Terminali">
    <meta property="og:description" content="Yapay zeka ile doğrulanmış 2 kelimelik yüksek likiditeli .com dijital marka varlıklarını canlı DNS sorgularıyla keşfedin.">
    <meta property="og:url" content="https://deedsa.com/">

    <!-- SCHEMA.ORG JSON-LD -->
    <script type="application/ld+json">
    {
      "@context": "https://schema.org",
      "@graph": [
        {
          "@type": "WebSite",
          "name": "DeedSa",
          "url": "https://deedsa.com/",
          "inLanguage": "tr-TR",
          "description": "Yapay zeka destekli e-ticaret alan adı keşfi, DNS doğrulama ve domain yatırım rehberi."
        },
        {
          "@type": "SoftwareApplication",
          "name": "DeedSa Enterprise Domain Intelligence",
          "applicationCategory": "BusinessApplication",
          "operatingSystem": "All",
          "url": "https://deedsa.com/",
          "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
          "description": "E-ticaret markaları ve domain yatırımcıları için yapay zeka destekli isim üretimi ve canlı DNS doğrulama terminali."
        },
        {
          "@type": "Organization",
          "name": "DeedSa Enterprise",
          "url": "https://deedsa.com/",
          "email": "support.deedsa@gmail.com"
        },
        {
          "@type": "FAQPage",
          "mainEntity": [
            {
              "@type": "Question",
              "name": "DeedSa alan adlarının boşta olduğunu nasıl kontrol ediyor?",
              "acceptedAnswer": {
                "@type": "Answer",
                "text": "DeedSa aday alan adları için A ve NS DNS kayıtlarını kontrol eder ve DNS açısından yanıt vermeyen adayları listelemeye çalışır. Tescil işlemi öncesinde kullanıcıların ilgili kayıt kuruluşunda son uygunluk kontrolünü yapması gerekir."
              }
            },
            {
              "@type": "Question",
              "name": "DeedSa affiliate bağlantılarından gelir elde ediyor mu?",
              "acceptedAnswer": {
                "@type": "Answer",
                "text": "Evet. DeedSa bazı bağlantılar üzerinden uygun bir kayıt, satın alma veya satış gerçekleştiğinde affiliate (iş ortaklığı) komisyonu elde edebilir. Bu, kullanıcıya DeedSa tarafından ayrıca bir ücret yansıtıldığı anlamına gelmez."
              }
            },
            {
              "@type": "Question",
              "name": "Namecheap ve Sedo bağlantılarından gitmek zorunlu mu?",
              "acceptedAnswer": {
                "@type": "Answer",
                "text": "Hayır. Bağlantılar isteğe bağlıdır. Kullanıcı ilgili hizmet sağlayıcının web sitesine bağımsız olarak da gidebilir."
              }
            }
          ]
        }
      ]
    }
    </script>

    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        :root {
            --font-main: 'Plus Jakarta Sans', -apple-system, sans-serif;
            --primary: #0284c7;
            --primary-dark: #0369a1;
            --primary-light: #f0f9ff;
            --border-color: #e2e8f0;
            --text-main: #0f172a;
            --text-muted: #64748b;
        }

        * { font-family: var(--font-main); box-sizing: border-box; scroll-behavior: smooth; }
        body { background-color: #f8fafc; color: var(--text-main); min-height: 100vh; display: flex; flex-direction: column; overflow-x: hidden; }
        main { flex: 1; }

        /* SİNEMATİK INTRO */
        #introOverlay {
            position: fixed; top: 0; left: 0; width: 100vw; height: 100vh;
            background: radial-gradient(circle at center, #1e293b 0%, #0f172a 60%, #020617 100%);
            z-index: 999999; display: flex; flex-direction: column; align-items: center; justify-content: center;
            transition: opacity 0.8s ease, visibility 0.8s ease; cursor: pointer;
        }
        #introCanvas { position: absolute; top: 0; left: 0; width: 100%; height: 100%; pointer-events: none; }
        .intro-content { position: relative; z-index: 2; text-align: center; animation: introReveal 1.6s cubic-bezier(0.16, 1, 0.3, 1) forwards; }
        @keyframes introReveal {
            0% { opacity: 0; transform: scale(0.85) translateY(20px); filter: blur(12px); }
            50% { opacity: 0.8; filter: blur(2px); }
            100% { opacity: 1; transform: scale(1) translateY(0); filter: blur(0); }
        }
        .intro-logo {
            font-size: 5rem; font-weight: 900; letter-spacing: 0.14em; color: #ffffff; text-transform: uppercase;
            text-shadow: 0 0 35px rgba(2, 132, 199, 0.6); margin-bottom: 8px;
            background: linear-gradient(135deg, #ffffff 30%, #38bdf8 70%, #0284c7 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        }
        .intro-tagline { color: #94a3b8; font-size: 1.05rem; letter-spacing: 0.28em; text-transform: uppercase; font-weight: 600; margin-bottom: 28px; }
        .intro-loader-line { width: 180px; height: 3px; background: rgba(255, 255, 255, 0.1); border-radius: 4px; margin: 0 auto; overflow: hidden; position: relative; }
        .intro-loader-bar { position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, #38bdf8, transparent); animation: loaderAnim 2s ease-in-out infinite; }
        @keyframes loaderAnim { 0% { left: -100%; } 100% { left: 100%; } }

        /* TOP NAVBAR */
        .top-navbar {
            background: rgba(255, 255, 255, 0.98); backdrop-filter: blur(10px);
            border-bottom: 1px solid var(--border-color); padding: 12px 32px;
            position: sticky; top: 0; z-index: 1000;
        }
        .brand-logo { font-size: 1.65rem; font-weight: 800; color: var(--primary); text-decoration: none; letter-spacing: -0.04em; margin-right: 36px; flex-shrink: 0; }
        .brand-logo:hover { color: var(--primary-dark); }
        .nav-links-wrap { display: flex; align-items: center; gap: 4px; flex-wrap: nowrap; }
        .nav-link-custom {
            color: #475569; font-weight: 600; font-size: 0.82rem; text-decoration: none;
            padding: 7px 11px; border-radius: 8px; transition: all 0.2s; cursor: pointer; white-space: nowrap;
        }
        .nav-link-custom:hover { color: var(--primary); background: var(--primary-light); }
        .nav-link-custom.active { color: var(--primary); background: var(--primary-light); font-weight: 700; }

        /* Dropdown Menüler */
        .dropdown-menu { border: 1px solid var(--border-color); box-shadow: 0 10px 25px rgba(0,0,0,0.08); border-radius: 12px; padding: 8px; margin-top: 6px; }
        .dropdown-item { font-size: 0.84rem; font-weight: 600; color: #334155; padding: 8px 12px; border-radius: 8px; transition: all 0.15s; }
        .dropdown-item:hover { background: var(--primary-light); color: var(--primary); }

        .api-status-dot { width: 8px; height: 8px; border-radius: 50%; background: #cbd5e1; display: inline-block; margin-right: 6px; }
        .api-status-dot.active { background: #22c55e; box-shadow: 0 0 8px rgba(34, 197, 94, 0.6); }

        /* Views */
        .view-section { display: none; padding-top: 10px; }
        .view-section.active { display: block; }

        /* Hero */
        .hero-banner { padding: 40px 0 24px; text-align: center; }
        .hero-title { font-size: 2.6rem; font-weight: 800; letter-spacing: -0.03em; color: var(--text-main); line-height: 1.2; max-width: 820px; margin: 0 auto 12px; }
        .hero-title span { color: var(--primary); }
        .hero-subtitle-pro { font-size: 1.05rem; color: #475569; font-weight: 500; max-width: 680px; margin: 0 auto 20px; line-height: 1.6; }
        .trust-pills {
            display: inline-flex; align-items: center; gap: 16px; background: #ffffff;
            border: 1px solid var(--border-color); padding: 6px 18px; border-radius: 30px;
            font-size: 0.82rem; font-weight: 700; color: #475569; margin-bottom: 14px; box-shadow: 0 2px 6px rgba(0,0,0,0.02);
        }

        /* Terminal Panel */
        .terminal-card { background: #ffffff; border: 1px solid var(--border-color); border-radius: 16px; padding: 32px; box-shadow: 0 10px 30px -10px rgba(0, 0, 0, 0.05); margin-bottom: 36px; }
        .field-label { font-size: 0.75rem; font-weight: 800; color: #475569; letter-spacing: 0.06em; text-transform: uppercase; margin-bottom: 8px; display: flex; justify-content: space-between; }
        .search-input { background-color: #ffffff; border: 1px solid #cbd5e1; border-radius: 10px; padding: 12px 16px; font-size: 0.95rem; }
        .search-input:focus { border-color: var(--primary); box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.12); outline: none; }
        .form-select-pro { background-color: #f8fafc; border: 1px solid #cbd5e1; border-radius: 10px; padding: 13px 18px; font-size: 0.96rem; color: #1e293b; font-weight: 600; }
        .btn-launch {
            background: var(--primary); color: #ffffff; font-weight: 700; border-radius: 10px;
            padding: 15px 24px; border: none; font-size: 1.02rem; display: inline-flex;
            align-items: center; justify-content: center; gap: 10px; transition: all 0.2s;
            box-shadow: 0 4px 12px rgba(2, 132, 199, 0.25); width: 100%;
        }
        .btn-launch:hover { background: var(--primary-dark); transform: translateY(-1px); }
        .btn-launch:disabled { opacity: 0.6; cursor: not-allowed; }

        /* Investment Cards */
        .investment-card { background: #ffffff; border: 1px solid var(--border-color); border-radius: 14px; padding: 24px; margin-bottom: 20px; transition: all 0.2s ease; }
        .investment-card:hover { border-color: var(--primary); box-shadow: 0 10px 30px rgba(2, 132, 199, 0.08); transform: translateY(-1px); }
        .domain-title { font-size: 1.5rem; font-weight: 800; color: #0f172a; letter-spacing: -0.02em; display: flex; align-items: center; gap: 8px; }
        .domain-tld { color: var(--primary); }
        .metric-badge { background: #f8fafc; border: 1px solid #e2e8f0; color: #475569; font-size: 0.78rem; font-weight: 700; padding: 5px 10px; border-radius: 8px; }
        .btn-action { background: #f8fafc; border: 1px solid #cbd5e1; color: #334155; font-size: 0.88rem; font-weight: 700; padding: 9px 16px; border-radius: 8px; text-decoration: none; transition: all 0.15s; display: inline-flex; align-items: center; gap: 6px; }
        .btn-action:hover { background: #0f172a; color: #ffffff; border-color: #0f172a; }
        .btn-register { background: #16a34a; border: 1px solid #16a34a; color: #ffffff; font-size: 0.88rem; font-weight: 700; padding: 9px 18px; border-radius: 8px; text-decoration: none; transition: all 0.15s; display: inline-flex; align-items: center; gap: 6px; }
        .btn-register:hover { background: #15803d; color: #ffffff; }

        .sedo-banner { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 12px; padding: 14px 18px; margin-top: 16px; display: flex; flex-direction: column; justify-content: space-between; gap: 12px; }
        @media (min-width: 768px) { .sedo-banner { flex-direction: row; align-items: center; } }
        .btn-sedo-blue { background: #0284c7; color: #ffffff !important; font-size: 0.86rem; font-weight: 700; padding: 8px 16px; border-radius: 8px; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; transition: all 0.2s; white-space: nowrap; border: none; }
        .btn-sedo-blue:hover { background: #0369a1; transform: translateY(-1px); box-shadow: 0 4px 12px rgba(2, 132, 199, 0.25); }

        /* ULTRA ZENGİN VE DOLU DOLU BLOG KARTLARI */
        .content-card { background: #ffffff; border: 1px solid var(--border-color); border-radius: 20px; padding: 56px; margin-bottom: 36px; box-shadow: 0 10px 35px -10px rgba(0,0,0,0.04); }
        .corporate-title { font-size: 2.6rem; font-weight: 900; color: #0f172a; letter-spacing: -0.03em; line-height: 1.25; margin-bottom: 22px; }
        .corporate-title span { background: linear-gradient(135deg, #0284c7, #0369a1); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
        .corporate-subtitle { font-size: 1.2rem; color: #475569; font-weight: 500; line-height: 1.8; margin-bottom: 40px; }
        .section-header-blue { font-size: 1.55rem; font-weight: 800; color: #0369a1; margin-top: 48px; margin-bottom: 20px; display: flex; align-items: center; gap: 12px; border-bottom: 2px solid #f0f9ff; padding-bottom: 8px; }
        .content-card p { font-size: 1.05rem; color: #334155; line-height: 1.95; margin-bottom: 24px; text-align: justify; }
        .content-card ul, .content-card ol { margin-bottom: 28px; padding-left: 24px; }
        .content-card li { font-size: 1.02rem; color: #334155; margin-bottom: 12px; line-height: 1.8; }
        .pro-callout-box { background: #f0f9ff; border: 1px solid #bae6fd; border-left: 6px solid #0284c7; border-radius: 14px; padding: 32px; margin: 36px 0; }
        .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 24px; margin: 32px 0; }
        .info-card-box { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 14px; padding: 26px; transition: all 0.2s; }
        .info-card-box h5 { font-size: 1.15rem; font-weight: 700; color: #0f172a; margin-bottom: 12px; display: flex; align-items: center; gap: 10px; }
        .info-card-box p { font-size: 0.95rem; color: #64748b; line-height: 1.7; margin-bottom: 0; text-align: left; }

        /* ROBOM WIDGET */
        .robom-launcher {
            position: fixed; bottom: 24px; right: 24px; width: 60px; height: 60px; border-radius: 50%;
            background: linear-gradient(135deg, #0284c7, #0f172a); color: #ffffff; display: flex;
            align-items: center; justify-content: center; cursor: pointer; box-shadow: 0 10px 25px rgba(2, 132, 199, 0.45);
            z-index: 9990; transition: all 0.3s cubic-bezier(0.175, 0.885, 0.32, 1.275); border: 2px solid #ffffff;
        }
        .robom-launcher:hover { transform: scale(1.08) rotate(5deg); }
        .robom-badge-pulse { position: absolute; top: 2px; right: 2px; width: 14px; height: 14px; background: #22c55e; border: 2px solid #ffffff; border-radius: 50%; }
        .robom-window {
            position: fixed; bottom: 92px; right: 24px; width: 410px; max-width: calc(100vw - 32px);
            height: min(580px, calc(100vh - 120px)); background: #ffffff; border-radius: 20px;
            box-shadow: 0 20px 50px rgba(15, 23, 42, 0.22); border: 1px solid var(--border-color); z-index: 9991;
            display: none; flex-direction: column; overflow: hidden; animation: robomPop 0.25s ease-out;
        }
        @keyframes robomPop { from { opacity: 0; transform: translateY(20px) scale(0.95); } to { opacity: 1; transform: translateY(0) scale(1); } }
        .robom-header { background: linear-gradient(135deg, #0284c7, #0369a1); color: #ffffff; padding: 14px 18px; display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; }
        .robom-avatar { width: 38px; height: 38px; background: rgba(255, 255, 255, 0.2); border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 1.2rem; }
        .robom-body { flex: 1; padding: 16px; overflow-y: auto; background: #f8fafc; display: flex; flex-direction: column; gap: 12px; }
        .chat-msg { max-width: 88%; padding: 12px 15px; border-radius: 14px; font-size: 0.88rem; line-height: 1.55; }
        .chat-msg.robom { background: #ffffff; border: 1px solid #e2e8f0; color: #1e293b; align-self: flex-start; border-bottom-left-radius: 4px; }
        .chat-msg.user { background: #0284c7; color: #ffffff; align-self: flex-end; border-bottom-right-radius: 4px; }
        .robom-suggestions { padding: 8px 12px; background: #ffffff; border-top: 1px solid #e2e8f0; display: flex; flex-direction: column; gap: 6px; max-height: 165px; overflow-y: auto; flex-shrink: 0; }
        .sugg-chip {
            background: #f0f9ff; border: 1px solid #bae6fd; color: #0369a1; font-size: 0.77rem; font-weight: 700;
            padding: 7px 11px; border-radius: 8px; cursor: pointer; text-align: left; transition: all 0.15s; display: flex; align-items: center; gap: 7px;
        }
        .sugg-chip:hover { background: #0284c7; color: #ffffff; border-color: #0284c7; }
        .robom-input-area { display: flex; padding: 10px 14px; background: #ffffff; border-top: 1px solid var(--border-color); gap: 8px; flex-shrink: 0; }
        .robom-input { flex: 1; border: 1px solid var(--border-color); border-radius: 10px; padding: 8px 12px; font-size: 0.88rem; outline: none; }
        .robom-input:focus { border-color: var(--primary); }
        .btn-robom-send { background: var(--primary); border: none; color: #ffffff; width: 38px; height: 38px; border-radius: 10px; display: flex; align-items: center; justify-content: center; cursor: pointer; }

        /* Footer */
        .footer { border-top: 1px solid var(--border-color); padding: 48px 0 32px; color: var(--text-muted); font-size: 0.88rem; margin-top: auto; background: #ffffff; }
        .footer-link { color: #64748b; text-decoration: none; transition: color 0.15s; cursor: pointer; margin: 0 10px; font-weight: 500; }
        .footer-link:hover { color: var(--primary); }
        .toast-copy { position: fixed; bottom: 24px; right: 24px; background: #0f172a; color: #ffffff; font-size: 0.9rem; font-weight: 700; padding: 14px 24px; border-radius: 10px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); z-index: 9999; display: none; }

        .seo-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(240px, 1fr)); gap: 18px; margin: 28px 0; }
        .seo-card { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 14px; padding: 22px; }
        .seo-card h5 { font-size: 1rem; font-weight: 800; color: #0f172a; margin-bottom: 10px; }
        .seo-card p { font-size: 0.94rem !important; line-height: 1.7 !important; margin-bottom: 0 !important; text-align: left !important; }
        .cta-panel { background: linear-gradient(135deg, #eff6ff, #f8fafc); border: 1px solid #bfdbfe; border-radius: 16px; padding: 28px; margin: 30px 0; }
        .cta-panel h4 { font-weight: 900; color: #0f172a; margin-bottom: 10px; }
        .legal-note { font-size: 0.9rem !important; color: #64748b !important; line-height: 1.7 !important; }
        .category-total { font-weight: 800; color: #0284c7; }
    </style>
</head>
<body>

    <!-- SİNEMATİK INTRO -->
    <div id="introOverlay" onclick="dismissIntro()">
        <canvas id="introCanvas"></canvas>
        <div class="intro-content">
            <div class="intro-logo">DEEDSA</div>
            <div class="intro-tagline">DOMAIN INTELLIGENCE TERMINAL</div>
            <div class="intro-loader-line"><div class="intro-loader-bar"></div></div>
        </div>
    </div>

    <!-- Header / Navbar -->
    <header class="top-navbar">
        <div class="container-fluid d-flex justify-content-between align-items-center px-lg-3">
            <div class="d-flex align-items-center justify-content-between w-100 justify-content-lg-start">
                <a href="#" onclick="switchView('terminal')" class="brand-logo">DeedSa</a>
                
                <button class="btn d-lg-none border-0 text-primary fs-3 p-1" type="button" data-bs-toggle="offcanvas" data-bs-target="#mobileOffcanvasMenu">
                    <i class="fa-solid fa-bars"></i>
                </button>
                
                <nav class="d-none d-lg-flex nav-links-wrap align-items-center">
                    <!-- ARAÇLAR DROPDOWN -->
                    <div class="dropdown">
                        <a class="nav-link-custom dropdown-toggle fw-bold" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <i class="fa-solid fa-toolbox me-1 text-primary"></i> Araçlar
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" onclick="switchView('terminal')"><i class="fa-solid fa-bolt text-primary me-2"></i> Alan Adı Keşif Motoru</a></li>
                            <li><a class="dropdown-item" href="#" onclick="openToolModal('social')"><i class="fa-solid fa-share-nodes text-success me-2"></i> Sosyal Medya Kullanıcı Adı Radarı</a></li>
                            <li><a class="dropdown-item" href="#" onclick="openToolModal('logo')"><i class="fa-solid fa-palette text-info me-2"></i> Yapay Zeka Logo & Mockup Üretici</a></li>
                            <li><a class="dropdown-item" href="#" onclick="openToolModal('pitchbook')"><i class="fa-solid fa-file-lines text-warning me-2"></i> E-Ticaret İş Planı (Pitchbook)</a></li>
                            <li><a class="dropdown-item" href="#" onclick="openToolModal('outbound')"><i class="fa-solid fa-envelope-open-text text-danger me-2"></i> Satış E-Postası (Outbound Pitch)</a></li>
                        </ul>
                    </div>

                    <!-- GEMINI API DROPDOWN -->
                    <div class="dropdown">
                        <a class="nav-link-custom dropdown-toggle fw-bold text-primary" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <span class="api-status-dot" id="headerApiStatusDot"></span>
                            <i class="fa-solid fa-key me-1"></i> Gemini API
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#apiKeyModal"><i class="fa-solid fa-gear text-success me-2"></i> API Anahtarını Bağla / Yönet</a></li>
                            <li><a class="dropdown-item" href="https://aistudio.google.com/app/apikey" target="_blank"><i class="fa-solid fa-circle-question text-info me-2"></i> Gemini API Nasıl Alınır?</a></li>
                        </ul>
                    </div>

                    <a onclick="switchView('whyToolsGuide')" class="nav-link-custom text-info fw-bold" id="navWhyToolsGuide"><i class="fa-solid fa-book-open me-1"></i> Araçlar Rehberi</a>
                    <a onclick="switchView('whyDeedsa')" class="nav-link-custom" id="navWhyDeedsa">Neden DeedSa?</a>
                    <a onclick="switchView('whyRobom')" class="nav-link-custom" id="navWhyRobom"><i class="fa-solid fa-robot text-primary me-1"></i> Robom AI Nedir?</a>
                    <a onclick="switchView('whyNamecheap')" class="nav-link-custom" id="navWhyNamecheap">Neden Namecheap?</a>
                    <a onclick="switchView('whySedo')" class="nav-link-custom" id="navWhySedo">Neden Sedo?</a>
                    <a onclick="switchView('howToEarn')" class="nav-link-custom" id="navHowToEarn">Nasıl Para Kazanılır?</a>
                    <a onclick="switchView('contact')" class="nav-link-custom" id="navContact"><i class="fa-solid fa-envelope text-primary me-1"></i> İletişim</a>
                </nav>
            </div>
        </div>
    </header>

    <!-- İNOVASYON ARAÇLARI MODALI -->
    <div class="modal fade" id="toolModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered modal-lg">
            <div class="modal-content border-0 shadow-lg" style="border-radius: 18px;">
                <div class="modal-header border-bottom-0 pb-0 pt-4 px-4">
                    <div class="d-flex align-items-center gap-2">
                        <div class="p-2 bg-primary-subtle text-primary rounded-3" id="toolModalIcon"><i class="fa-solid fa-toolbox fs-5"></i></div>
                        <div>
                            <h5 class="modal-title fw-bold text-dark" id="toolModalTitle">DeedSa İnovasyon Aracı</h5>
                            <p class="small text-secondary mb-0" id="toolModalSubtitle">Seçilen alan adı veya niş için akıllı analiz motoru.</p>
                        </div>
                    </div>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <div class="modal-body px-4 py-4" id="toolModalBody"></div>
                <div class="modal-footer border-top-0 pt-0 px-4 pb-4">
                    <button type="button" class="btn btn-light px-4 py-2 fw-bold text-secondary rounded-3" data-bs-dismiss="modal">Kapat</button>
                </div>
            </div>
        </div>
    </div>

    <!-- GEMINI API KEY MODALI -->
    <div class="modal fade" id="apiKeyModal" tabindex="-1" aria-hidden="true">
        <div class="modal-dialog modal-dialog-centered">
            <div class="modal-content border-0 shadow-lg" style="border-radius: 18px;">
                <div class="modal-header border-bottom-0 pb-0 pt-4 px-4">
                    <div class="d-flex align-items-center gap-2">
                        <div class="p-2 bg-primary-subtle text-primary rounded-3"><i class="fa-solid fa-key fs-5"></i></div>
                        <div>
                            <h5 class="modal-title fw-bold text-dark">Google Gemini API Yönetimi</h5>
                            <p class="small text-secondary mb-0">API Anahtarınız güvenle yalnızca tarayıcınızda tutulur.</p>
                        </div>
                    </div>
                    <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Kapat"></button>
                </div>
                <div class="modal-body px-4 py-4">
                    <div class="mb-3">
                        <label class="field-label mb-2">API ANAHTARINIZ</label>
                        <div class="input-group">
                            <input type="password" id="modalApiKeyInput" class="form-control search-input" placeholder="Geçerli API Anahtarınızı Yapıştırın" style="font-family: monospace;">
                            <button class="btn btn-outline-secondary" type="button" onclick="toggleApiKeyVisibility()" id="btnToggleVisibility"><i class="fa-regular fa-eye"></i></button>
                        </div>
                        <div class="form-text small mt-2 text-muted">
                            <i class="fa-solid fa-shield-halved text-success me-1"></i> Sıfır Bilgi Güvenliği: Anahtarınız DeedSa veritabanına asla kaydedilmez.
                        </div>
                    </div>
                    <div class="p-3 bg-light rounded-3 border mb-3">
                        <div class="d-flex justify-content-between align-items-center">
                            <span class="small text-secondary">Henüz API anahtarınız yok mu?</span>
                            <a href="https://aistudio.google.com/app/apikey" target="_blank" class="small fw-bold text-primary text-decoration-none">
                                Ücretsiz Anahtar Al <i class="fa-solid fa-arrow-up-right-from-square ms-1"></i>
                            </a>
                        </div>
                    </div>
                </div>
                <div class="modal-footer border-top-0 pt-0 px-4 pb-4 d-flex justify-content-between">
                    <button type="button" class="btn btn-outline-danger px-3 py-2 fw-bold rounded-3" id="btnModalDeleteKey" onclick="modalDeleteApiKey()" style="display: none;">
                        <i class="fa-solid fa-trash-can me-1"></i> Sil
                    </button>
                    <div class="d-flex gap-2 ms-auto">
                        <button type="button" class="btn btn-light px-3 py-2 fw-bold text-secondary rounded-3" data-bs-dismiss="modal">Kapat</button>
                        <button type="button" class="btn btn-primary px-4 py-2 fw-bold rounded-3" onclick="modalSaveApiKey()">
                            <i class="fa-solid fa-check me-1"></i> Kaydet & Bağla
                        </button>
                    </div>
                </div>
            </div>
        </div>
    </div>

    <!-- TERMINAL (ANA EKRAN) -->
    <main class="container py-4 view-section active" id="viewTerminal">
        <div class="hero-banner">
            <div class="trust-pills">
                <span><i class="fa-solid fa-robot text-primary me-1"></i> Robom Akıllı Asistan</span>
                <span><i class="fa-solid fa-shield-check text-success me-1"></i> WAF Korumalı Analiz</span>
                <span><i class="fa-solid fa-lock text-secondary me-1"></i> Sıfır Bilgi Gizlilik Mimarisi</span>
            </div>
            <h1 class="hero-title">E-Ticaret Alan Adı <span>Keşif ve Analiz Terminali</span></h1>
            <p class="hero-subtitle-pro">Yüzlerce mikro-niş e-ticaret kategorisinde küresel markaların isim yapıları analiz edilir; doğrulanmış, yüksek potansiyelli ve boşta .com portföyü listelenir.</p>
        </div>

        <div class="terminal-card">
            <form id="searchForm">
                <div class="row g-4">
                    <div class="col-md-5">
                        <label class="field-label">SEKTÖR FİLTRELEME <span class="text-primary" id="categoryCount">(Tüm Nişler)</span></label>
                        <input type="text" id="categorySearch" class="form-control search-input" placeholder="Kelime ile filtrele (örn: Retinol, Masaj, Giyim, Bebek)...">
                    </div>
                    <div class="col-md-7">
                        <label class="field-label">HEDEFLENEN E-TİCARET NİŞİ</label>
                        <select id="category" class="form-select form-select-pro">
                            <option value="Anti-Aging and Anti-Wrinkle Skincare">Anti-Aging ve Kırışıklık Karşıtı Cilt Bakımı</option>
                            <option value="Retinol and Peptide Night Serums">Retinol ve Peptit Gece Serumları</option>
                            <option value="Vitamin C and Brightening Face Serums">C Vitamini ve Aydınlatıcı Yüz Bakımı</option>
                            <option value="Hyaluronic Acid Hydrating Creams">Hyaluronik Asit Nemlendiricileri</option>
                            <option value="Daily Sunscreen and SPF Protection Care">Güneş Koruyucu ve SPF Bakım Kremleri</option>
                            <option value="Acne and Blemish Clearing Care">Akne ve Leke Karşıtı Bakım Ürünleri</option>
                            <option value="Red Light LED Therapy Face Masks">Kırmızı Işık (LED) Terapi Yüz Maskeleri</option>
                            <option value="Ultrasonic Skin Scrubber and Peeling Devices">Ultrasonik Cilt Temizleme Cihazları</option>
                            <option value="Micro-Needle Derma Rollers for Skin and Hair">Mikroiğneli Dermaroller Setleri</option>
                            <option value="Under-Eye Dark Circle and Puffiness Creams">Göz Altı Morluk ve Torba Bakım Kremleri</option>
                            <option value="K-Beauty Korean Glass Skin Products">K-Beauty Kore Cilt Bakım Ürünleri</option>
                            <option value="Giyim ve Moda">Giyim ve Moda</option>
                            <option value="Kadın Giyim">Kadın Giyim</option>
                            <option value="Erkek Giyim">Erkek Giyim</option>
                            <option value="Çocuk Giyim">Çocuk Giyim</option>
                            <option value="Ayakkabı ve Çanta">Ayakkabı ve Çanta</option>
                            <option value="Elektronik">Elektronik</option>
                            <option value="Cep Telefonu ve Aksesuar">Cep Telefonu ve Aksesuar</option>
                            <option value="Bilgisayar ve Tablet">Bilgisayar ve Tablet</option>
                            <option value="Ev ve Yaşam">Ev ve Yaşam</option>
                            <option value="Mutfak Gereçleri">Mutfak Gereçleri</option>
                            <option value="Mobilya">Mobilya</option>
                            <option value="Kişisel Bakım ve Kozmetik">Kişisel Bakım ve Kozmetik</option>
                            <option value="Spor ve Outdoor">Spor ve Outdoor</option>
                            <option value="Evcil Hayvan Ürünleri">Evcil Hayvan Ürünleri</option>
                            <option value="Otomotiv ve Motosiklet">Otomotiv ve Motosiklet</option>
                            <option value="Kahve ve Çay Ekipmanları">Kahve ve Çay Ekipmanları</option>
                            <option value="Bebek Beslenme Ürünleri">Bebek Beslenme Ürünleri</option>
                            <option value="Akıllı Ev Teknolojileri">Akıllı Ev Teknolojileri</option>
                            <option value="Dijital Ürünler ve Lisanslar">Dijital Ürünler ve Lisanslar</option>

                            <option value="Doğal Cilt Bakımı">Doğal Cilt Bakımı</option>
                            <option value="Niacinamide Serumları">Niacinamide Serumları</option>
                            <option value="Ceramide Skin Barrier Care">Seramid Cilt Bariyeri Bakımı</option>
                            <option value="Body Care and Body Lotions">Vücut Bakımı ve Losyonları</option>
                            <option value="Hair Care and Scalp Care">Saç ve Saç Derisi Bakımı</option>
                            <option value="Curly Hair Products">Kıvırcık Saç Ürünleri</option>
                            <option value="Hair Styling Tools">Saç Şekillendirme Cihazları</option>
                            <option value="Men's Grooming">Erkek Bakım Ürünleri</option>
                            <option value="Perfume and Fragrance">Parfüm ve Koku</option>
                            <option value="Beauty Tools and Accessories">Güzellik Aletleri ve Aksesuarları</option>
                            <option value="Minimalist Jewelry">Minimalist Takılar</option>
                            <option value="Watches and Accessories">Saatler ve Aksesuarlar</option>
                            <option value="Streetwear">Sokak Giyimi</option>
                            <option value="Athleisure">Günlük Spor Giyim</option>
                            <option value="Activewear">Spor Giyim</option>
                            <option value="Modest Fashion">Tesettür ve Modern Mütevazı Moda</option>
                            <option value="Wedding Accessories">Düğün Aksesuarları</option>
                            <option value="Travel Bags and Organizers">Seyahat Çantaları ve Organizerlar</option>
                            <option value="Home Office Accessories">Ev Ofis Aksesuarları</option>
                            <option value="Desk Organization">Masa Düzenleme Ürünleri</option>
                            <option value="Smart Lighting">Akıllı Aydınlatma</option>
                            <option value="Decorative Lighting">Dekoratif Aydınlatma</option>
                            <option value="Wall Art and Posters">Duvar Sanatı ve Posterler</option>
                            <option value="Candles and Home Fragrance">Mum ve Ev Kokuları</option>
                            <option value="Bedding and Bedroom">Yatak ve Yatak Odası Ürünleri</option>
                            <option value="Bathroom Accessories">Banyo Aksesuarları</option>
                            <option value="Storage and Organization">Depolama ve Düzenleme</option>
                            <option value="Garden and Balcony">Bahçe ve Balkon</option>
                            <option value="Indoor Plants and Planters">İç Mekan Bitkileri ve Saksılar</option>
                            <option value="DIY Tools and Craft Supplies">DIY Aletleri ve Hobi Malzemeleri</option>
                            <option value="3D Printing Accessories">3D Baskı Aksesuarları</option>
                            <option value="Gaming Accessories">Oyuncu Aksesuarları</option>
                            <option value="Mechanical Keyboards">Mekanik Klavyeler</option>
                            <option value="PC Desk Setup">PC Masa Kurulumları</option>
                            <option value="Webcams and Streaming Gear">Web Kameraları ve Yayın Ekipmanları</option>
                            <option value="Audio Accessories">Ses Ekipmanları ve Aksesuarları</option>
                            <option value="Portable Chargers and Power Banks">Taşınabilir Şarj ve Powerbank</option>
                            <option value="Smart Wearables">Akıllı Giyilebilir Teknolojiler</option>
                            <option value="Phone Cases and Covers">Telefon Kılıfları ve Kapakları</option>
                            <option value="Tablet Accessories">Tablet Aksesuarları</option>
                            <option value="Camera Accessories">Kamera Aksesuarları</option>
                            <option value="Travel Electronics">Seyahat Elektroniği</option>
                            <option value="Cycling Accessories">Bisiklet Aksesuarları</option>
                            <option value="Running Accessories">Koşu Aksesuarları</option>
                            <option value="Yoga and Pilates">Yoga ve Pilates</option>
                            <option value="Home Fitness Equipment">Ev Fitness Ekipmanları</option>
                            <option value="Hiking and Camping Gear">Doğa Yürüyüşü ve Kamp</option>
                            <option value="Fishing Accessories">Balıkçılık Aksesuarları</option>
                            <option value="Golf Accessories">Golf Aksesuarları</option>
                            <option value="Skate and Board Sports">Kaykay ve Board Sporları</option>
                            <option value="Pet Grooming">Evcil Hayvan Bakımı</option>
                            <option value="Dog Walking Accessories">Köpek Gezdirme Aksesuarları</option>
                            <option value="Cat Enrichment Products">Kedi Oyuncak ve Zenginleştirme Ürünleri</option>
                            <option value="Aquarium Supplies">Akvaryum Malzemeleri</option>
                            <option value="Pet Travel Products">Evcil Hayvan Seyahat Ürünleri</option>
                            <option value="Car Interior Accessories">Otomobil İç Aksesuarları</option>
                            <option value="Car Care and Detailing">Araç Bakım ve Detaylandırma</option>
                            <option value="Motorcycle Accessories">Motosiklet Aksesuarları</option>
                            <option value="EV Accessories">Elektrikli Araç Aksesuarları</option>
                            <option value="Car Organization">Araç İçi Düzenleme</option>
                            <option value="Coffee Brewing Tools">Kahve Demleme Ekipmanları</option>
                            <option value="Matcha and Tea Accessories">Matcha ve Çay Aksesuarları</option>
                            <option value="Baking Tools and Accessories">Pasta ve Fırıncılık Ekipmanları</option>
                            <option value="Meal Prep Accessories">Meal Prep Hazırlık Ürünleri</option>
                            <option value="Kitchen Storage">Mutfak Depolama</option>
                            <option value="Reusable Drinkware">Yeniden Kullanılabilir İçecek Kapları</option>
                            <option value="Specialty Food Gifts">Özel Gıda Hediye Setleri</option>
                            <option value="Board Games">Kutu Oyunları</option>
                            <option value="Arts and Drawing Supplies">Sanat ve Çizim Malzemeleri</option>
                            <option value="Stationery and Journaling">Kırtasiye ve Günlük Tutma</option>
                            <option value="Kids Learning Products">Çocuk Eğitim Ürünleri</option>
                            <option value="Travel Accessories">Seyahat Aksesuarları</option>
                            <option value="Luggage and Carry On">Valiz ve Kabin Çantaları</option>
                            <option value="Sustainable Products">Sürdürülebilir Ürünler</option>
                            <option value="Eco Friendly Home Products">Çevre Dostu Ev Ürünleri</option>
                            <option value="Digital Templates">Dijital Şablonlar</option>
                            <option value="Notion Templates">Notion Şablonları</option>
                            <option value="Printables and Planners">Yazdırılabilir Planlayıcılar</option>
                            <option value="Natural Supplements and Wellness Products">Doğal Wellness Ürünleri</option>
                            <option value="Sleep and Relaxation Products">Uyku ve Rahatlama Ürünleri</option>
                            <option value="Aromatherapy Products">Aromaterapi Ürünleri</option>
                            <option value="Massage and Recovery Tools">Masaj ve Toparlanma Aletleri</option>
                            <option value="Home Spa Products">Ev Spa Ürünleri</option>
                            <option value="Oral Care Products">Ağız ve Diş Bakım Ürünleri</option>
                            <option value="Electric Toothbrush Accessories">Elektrikli Diş Fırçası Aksesuarları</option>
                            <option value="Natural Deodorants">Doğal Deodorantlar</option>
                            <option value="Menstrual Care Products">Menstrüel Bakım Ürünleri</option>
                            <option value="Baby Care Essentials">Bebek Bakım Ürünleri</option>
                            <option value="Montessori Toys">Montessori Oyuncakları</option>
                            <option value="Educational Toys">Eğitici Oyuncaklar</option>
                            <option value="Kids STEM Kits">Çocuk STEM Kitleri</option>
                            <option value="Baby Nursery Decor">Bebek Odası Dekorasyonu</option>
                            <option value="Diaper Bag Accessories">Bebek Çantası Aksesuarları</option>
                            <option value="Toddler Feeding Accessories">Çocuk Beslenme Aksesuarları</option>
                            <option value="School Supplies">Okul Kırtasiye Ürünleri</option>
                            <option value="Language Learning Products">Dil Öğrenme Ürünleri</option>
                            <option value="Pet Nutrition Accessories">Evcil Hayvan Beslenme Aksesuarları</option>
                            <option value="Dog Training Supplies">Köpek Eğitim Ürünleri</option>
                            <option value="Cat Furniture">Kedi Mobilyaları</option>
                            <option value="Bird Supplies">Kuş Ürünleri</option>
                            <option value="Reptile Supplies">Sürüngen Ürünleri</option>
                            <option value="Horse Riding Accessories">Binicilik Aksesuarları</option>
                            <option value="Pool and Spa Accessories">Havuz ve Spa Aksesuarları</option>
                            <option value="Outdoor Furniture">Bahçe ve Outdoor Mobilyaları</option>
                            <option value="BBQ and Grilling Accessories">Mangal ve Izgara Aksesuarları</option>
                            <option value="Picnic Accessories">Piknik Aksesuarları</option>
                            <option value="Camping Kitchen Gear">Kamp Mutfak Ekipmanları</option>
                            <option value="Travel Safety Accessories">Seyahat Güvenlik Aksesuarları</option>
                            <option value="Passport and Document Organizers">Pasaport ve Belge Organizerları</option>
                            <option value="Beach Accessories">Plaj Aksesuarları</option>
                            <option value="Swimwear and Beachwear">Mayo ve Plaj Giyimi</option>
                            <option value="Ski and Snowboard Accessories">Kayak ve Snowboard Aksesuarları</option>
                            <option value="Tennis Accessories">Tenis Aksesuarları</option>
                            <option value="Basketball Accessories">Basketbol Aksesuarları</option>
                            <option value="Football Training Gear">Futbol Antrenman Ekipmanları</option>
                            <option value="Martial Arts Gear">Dövüş Sporları Ekipmanları</option>
                            <option value="Dancewear and Accessories">Dans Kıyafetleri ve Aksesuarları</option>
                            <option value="Home Gym Accessories">Ev Spor Salonu Aksesuarları</option>
                            <option value="Resistance Bands">Direnç Bantları</option>
                            <option value="Mobility and Stretching Tools">Mobilite ve Esneme Aletleri</option>
                            <option value="Cycling Apparel">Bisiklet Giyim Ürünleri</option>
                            <option value="E-Bike Accessories">E-Bisiklet Aksesuarları</option>
                            <option value="Car Electronics">Otomobil Elektroniği</option>
                            <option value="Dash Cameras">Araç Kameraları</option>
                            <option value="Car Audio Accessories">Araç Ses Sistemi Aksesuarları</option>
                            <option value="EV Charging Accessories">Elektrikli Araç Şarj Aksesuarları</option>
                            <option value="Motorcycle Riding Gear">Motosiklet Sürüş Ekipmanları</option>
                            <option value="Garage Organization">Garaj Düzenleme Ürünleri</option>
                            <option value="Tools and Workshop Equipment">Alet ve Atölye Ekipmanları</option>
                            <option value="Power Tools Accessories">Elektrikli Alet Aksesuarları</option>
                            <option value="Home Security Products">Ev Güvenlik Ürünleri</option>
                            <option value="Smart Doorbells">Akıllı Kapı Zilleri</option>
                            <option value="Home Air Quality Devices">Ev Hava Kalitesi Cihazları</option>
                            <option value="Water Filtration Products">Su Filtreleme Ürünleri</option>
                            <option value="Laundry Organization">Çamaşır Düzenleme Ürünleri</option>
                            <option value="Cleaning Tools and Accessories">Temizlik Aletleri ve Aksesuarları</option>
                            <option value="Kitchen Organization">Mutfak Düzenleme Ürünleri</option>
                            <option value="Cookware Accessories">Pişirme Gereçleri Aksesuarları</option>
                            <option value="Food Storage Containers">Gıda Saklama Kapları</option>
                            <option value="Coffee Storage">Kahve Saklama Ürünleri</option>
                            <option value="Tea Brewing Accessories">Çay Demleme Aksesuarları</option>
                            <option value="Home Bar Accessories">Ev Barı Aksesuarları</option>
                            <option value="Baking Decor Supplies">Pasta Dekorasyon Malzemeleri</option>
                            <option value="Craft Kits">Hobi ve El İşi Kitleri</option>
                            <option value="Sewing Accessories">Dikiş Aksesuarları</option>
                            <option value="Knitting Supplies">Örgü Malzemeleri</option>
                            <option value="Photography Props">Fotoğrafçılık Aksesuarları</option>
                            <option value="Content Creator Accessories">İçerik Üreticisi Aksesuarları</option>
                            <option value="Microphone Accessories">Mikrofon Aksesuarları</option>
                            <option value="Laptop Accessories">Dizüstü Bilgisayar Aksesuarları</option>
                            <option value="Monitor Accessories">Monitör Aksesuarları</option>
                            <option value="Networking Equipment">Ağ Ekipmanları</option>
                            <option value="USB Accessories">USB Aksesuarları</option>
                            <option value="Smart Home Sensors">Akıllı Ev Sensörleri</option>
                            <option value="Home Energy Monitoring">Ev Enerji Takip Ürünleri</option>
                            <option value="Digital Art Resources">Dijital Sanat Kaynakları</option>
                            <option value="Online Course Templates">Online Kurs Şablonları</option>
                            <option value="Business Document Templates">İş Dokümanı Şablonları</option>
                            <option value="Resume Templates">CV ve Özgeçmiş Şablonları</option>
                            <option value="Invoice Templates">Fatura Şablonları</option>
                            <option value="Presentation Templates">Sunum Şablonları</option>
                            <option value="Social Media Templates">Sosyal Medya Şablonları</option>
                            <option value="Email Marketing Templates">E-Posta Tanıtım Şablonları</option>
                            <option value="Small Business Software">Küçük İşletme Yazılımları</option>
                            <option value="Productivity Tools">Verimlilik Araçları</option>
                        </select>
                    </div>
                </div>

                <div class="mt-4">
                    <button type="submit" id="submitBtn" class="btn-launch">
                        <i class="fa-solid fa-bolt me-2"></i> <span>Boşta Olan E-Ticaret .COM Alan Adlarını Tara</span>
                    </button>
                </div>
            </form>
        </div>

        <div id="loading" class="text-center my-5 d-none">
            <div class="spinner-border text-primary" role="status" style="width: 2.5rem; height: 2.5rem;"></div>
            <div class="text-dark fw-bold mt-3">E-Ticaret Pazar Verileri Taranıyor...</div>
            <p class="text-secondary small mt-1">Canlı DNS ve RDAP tescil durumu ile marka uyumu filtreleniyor.</p>
        </div>

        <div id="resultsContainer" class="d-none">
            <div class="d-flex justify-content-between align-items-center mb-4">
                <div>
                    <h3 class="fw-bold mb-1 text-dark">Tescile Uygun Portföy</h3>
                    <p class="text-secondary small mb-0" id="resultCountInfo">Doğrulanmış ve boşta olan alan adları listelenmektedir.</p>
                </div>
                <button class="btn btn-action" id="exportBtn" onclick="exportCSV()">
                    <i class="fa-solid fa-file-csv me-1 text-success"></i> <span>Portföyü CSV İndir</span>
                </button>
            </div>
            <div id="domainList"></div>
        </div>
    </main>

    <!-- BLOG SAYFALARI (DOLU DOLU & KURUMSAL) -->
    <main class="container py-5 view-section" id="viewWhyToolsGuide">
        <div class="row justify-content-center"><div class="col-lg-10"><div class="content-card">
            <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">İnovasyon & SaaS Ekosistemi</span>
            <h1 class="corporate-title">DeedSa <span>Araçlar Ekosistemi</span>: Fikirden Markaya Giden Yol</h1>
            <p class="corporate-subtitle">DeedSa yalnızca alan adı arayan bir ekran değil; isim keşfi, marka değerlendirmesi, sosyal medya hazırlığı, görsel kimlik, iş planı ve satış iletişimini tek akışta birleştiren yardımcı araçlar katmanıdır.</p>
            <div class="seo-grid">
                <div class="seo-card"><h5>1. Alan Adı Keşif Motoru</h5><p>Niş seçimine göre marka hissi taşıyan iki kelimelik adaylar üretir ve DNS kontrolünden geçen adayları öne çıkarır.</p></div>
                <div class="seo-card"><h5>2. Sosyal Medya Radarı</h5><p>Marka adının sosyal kullanıcı adı olarak değerlendirilmesi için hızlı bir ön kontrol katmanı sunar. Gerçek platform uygunluğu ayrıca doğrulanmalıdır.</p></div>
                <div class="seo-card"><h5>3. Logo & Mockup</h5><p>Yeni isim üzerinde ilk marka algısını oluşturmak için görsel bir sunum katmanı sağlar.</p></div>
                <div class="seo-card"><h5>4. Pitchbook</h5><p>Seçilen niş için hedef kitle, büyüme mantığı ve ilk dönem tanıtım planını düşünmeye yardımcı olur.</p></div>
                <div class="seo-card"><h5>5. Outbound Pitch</h5><p>Domain yatırımcılarının potansiyel kurumsal alıcılara daha net ve profesyonel ulaşmasına yardımcı olacak teklif metni yaklaşımı sunar.</p></div>
                <div class="seo-card"><h5>6. Robom AI</h5><p>E-ticaret, marka isimlendirme ve domain planı hakkında hızlı düşünme partneri olarak kullanılabilir.</p></div>
            </div>
            <h3 class="section-header-blue"><i class="fa-solid fa-route"></i> En verimli kullanım sırası</h3>
            <p>Önce nişi daraltın, ardından aday isimleri keşfedin. Beğendiğiniz isimleri marka dili, telaffuz, yazım kolaylığı ve hedef müşterinin zihnindeki çağrışımı açısından değerlendirin. Sonrasında DNS kontrolünden geçen adayları kayıt kuruluşunda yeniden doğrulayın ve marka/hukuk araştırmasını tamamlayın.</p>
            <div class="cta-panel"><h4>Tek ekrandan daha az sürtünmeyle ilerleyin</h4><p class="mb-3">İsim bulmak çoğu zaman fikir eksikliğinden değil, seçenek fazlalığından zorlaşır. DeedSa araçlarını ardışık kullanarak karar sürecini küçük adımlara bölmek daha sağlıklı bir yaklaşım sağlar.</p><button class="btn btn-primary fw-bold" onclick="switchView('terminal')">Alan Adı Keşfine Dön</button></div>
            <p class="legal-note">Not: Araç sonuçları araştırma ve fikir üretme amaçlıdır. Sosyal medya kullanıcı adı, marka tescili, domain kayıt durumu ve ticari uygunluk için ilgili üçüncü taraf kaynaklarda ayrıca doğrulama yapın.</p>
        </div></div></div>
    </main>

    <main class="container py-5 view-section" id="viewWhyDeedsa">
        <div class="row justify-content-center"><div class="col-lg-10"><div class="content-card">
            <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">İstihbarat ve Marka Seçimi</span>
            <h1 class="corporate-title">Neden <span>DeedSa</span> ile Domain Keşfi?</h1>
            <p class="corporate-subtitle">İyi bir domain yalnızca boşta olan bir kelime çifti değildir. Hatırlanabilirlik, telaffuz, görsel görünüm, kategori uyumu ve olası ticari kullanım birlikte düşünülmelidir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-brain"></i> İnsanların isimleri nasıl değerlendirdiğine odaklanın</h3>
            <p>Bir kullanıcı bir marka adını ilk gördüğünde saniyeler içinde “kolay mı, güvenilir mi, premium mu, ne sattığını çağrıştırıyor mu?” gibi sezgisel sorulara cevap verir. Bu nedenle kısa, ritmik ve yazımı kolay isimler daha güçlü adaylar olabilir. Ancak iyi algı tek başına ticari başarı garantisi değildir.</p>
            <div class="info-grid">
                <div class="info-card-box"><h5><i class="fa-solid fa-ear-listen text-primary"></i> Fonetik</h5><p>Ses uyumu ve kolay telaffuz, markanın ağızdan ağıza aktarılmasını kolaylaştırabilir.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-eye text-info"></i> Görsel Hafıza</h5><p>Temiz harf dizilimi ve karmaşık olmayan yazım biçimi, ismi tekrar yazmayı kolaylaştırır.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-bullseye text-danger"></i> Niş Uyumu</h5><p>İsim, hedeflenen ürün veya kategori ile uyumlu bir marka hissi vermelidir.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-shield text-success"></i> Hukuki Kontrol</h5><p>Benzer marka, şirket ve domain kullanımlarını kayıt öncesi ayrıca araştırmak kritik bir adımdır.</p></div>
            </div>
            <h3 class="section-header-blue"><i class="fa-solid fa-filter"></i> DeedSa'yı karar filtresi olarak kullanın</h3>
            <p>En yüksek skoru otomatik olarak “en iyi yatırım” kabul etmek yerine, birkaç aday seçip insan gözüyle değerlendirin. Sonrasında domain kaydını ilgili registrar üzerinde tekrar doğrulayın ve hedef pazarda marka taraması yapın.</p>
            <div class="cta-panel"><h4>Daha iyi isim, daha net marka hikâyesi</h4><p class="mb-3">Önce müşterinin hangi duyguyu hatırlamasını istediğinize karar verin; sonra domain adaylarını bu hedefe göre eleyin.</p><button class="btn btn-primary fw-bold" onclick="switchView('terminal')">Yeni Niş Seç ve Tara</button></div>
        </div></div></div>
    </main>

    <main class="container py-5 view-section" id="viewWhyRobom">
        <div class="row justify-content-center"><div class="col-lg-10"><div class="content-card">
            <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Yapay Zeka Asistanı</span>
            <h1 class="corporate-title">Robom AI Nedir? <span>İşinizi Nasıl Kolaylaştırır?</span></h1>
            <p class="corporate-subtitle">Robom, DeedSa içinde hızlı fikir alışverişi yapmak, bir domain adayını farklı açılardan düşünmek ve e-ticaret kararlarını çerçevelemek için tasarlanmış sohbet asistanıdır.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-comments"></i> Robom ile hangi sorular sorulabilir?</h3>
            <div class="seo-grid">
                <div class="seo-card"><h5>Marka Fonetiği</h5><p>Bir isim kulağa nasıl geliyor, telaffuzu kolay mı ve hangi marka hissini veriyor?</p></div>
                <div class="seo-card"><h5>Niş Planı</h5><p>Hangi müşteri segmentine konuşulmalı, teklif nasıl konumlandırılmalı?</p></div>
                <div class="seo-card"><h5>Domain Satış Hikâyesi</h5><p>Bir domain potansiyel alıcıya hangi ticari kullanım senaryolarıyla anlatılabilir?</p></div>
                <div class="seo-card"><h5>İlk 90 Gün</h5><p>Yeni bir e-ticaret projesi için ölçülebilir bir başlangıç planı nasıl kurulabilir?</p></div>
            </div>
            <h3 class="section-header-blue"><i class="fa-solid fa-lightbulb"></i> En iyi sonuç için</h3>
            <p>Robom'a “iyi mi?” gibi tek cümlelik sorular yerine bağlam verin: hedef ülke, ürün grubu, müşteri profili, fiyat seviyesi ve marka tonu. Böylece alınan fikirleri karar kriterleriyle karşılaştırabilirsiniz.</p>
            <p class="legal-note">Robom'un yanıtları yapay zeka üretimidir. Önemli hukuki, finansal veya marka kararlarını bağımsız kaynaklarla doğrulayın.</p>
        </div></div></div>
    </main>

    <main class="container py-5 view-section" id="viewWhyNamecheap">
        <div class="row justify-content-center"><div class="col-lg-10"><div class="content-card">
            <span class="badge bg-success-subtle text-success fw-bold px-3 py-2 rounded-pill mb-3">Tescil & Akıllı Satın Alma</span>
            <h1 class="corporate-title">Neden <span>Namecheap</span> ile Tescil Etmelisiniz?</h1>
            <p class="corporate-subtitle">İyi bir domaini bulduktan sonra kararın ikinci kısmı güvenilir ve şeffaf bir kayıt deneyimidir. Namecheap, domain kayıt hizmetleri yanında hosting, SSL ve başka web ürünleri de sunan bir sağlayıcıdır.</p>
            <div class="pro-callout-box"><h5 class="fw-bold mb-2"><i class="fa-solid fa-tags me-2 text-success"></i> Kampanyaları kontrol edin</h5><p class="mb-0">Namecheap kampanyaları dönem dönem değişir. Bazı uygun domainlerde %40 civarında veya daha yüksek indirimler görülebilir; <strong>kesin güncel oranı ödeme ve teklif ekranında kontrol edin.</strong> DeedSa bağlantısını kullanmak kullanıcıya DeedSa tarafından ayrıca bir ücret eklenmesi anlamına gelmez.</p></div>
            <h3 class="section-header-blue"><i class="fa-solid fa-brain"></i> Sağlam Karar İçin Değer Kontrolü</h3>
            <p>Buradaki hedef baskı kurmak değil, satın alma kararındaki gereksiz sürtünmeyi azaltmaktır. Kullanıcı önce toplam maliyeti görür, sonra domainin neden değerli olduğunu anlar ve son olarak güvenilir bir kayıt adımına geçer. Bu nedenle DeedSa'da CTA (eyleme çağrı) mesajı net, fayda odaklı ve koşullu tutulur.</p>
            <div class="info-grid">
                <div class="info-card-box"><h5><i class="fa-solid fa-magnifying-glass-dollar text-primary"></i> Fiyatı doğrula</h5><p>Kampanya yüzdesine değil, satın alma ekranındaki nihai fiyata odaklanın.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-clock text-info"></i> Karar sürtünmesini azalt</h5><p>Tek bir net CTA, kullanıcıyı gereksiz yönlendirmelerden kurtarır.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-user-plus text-success"></i> Yeni müşteri avantajı</h5><p>Namecheap affiliate sistemi, yeni müşterilerin yönlendirilmesine dayalıdır; uygun kampanyalar kullanıcı deneyimine göre değişebilir.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-lock text-secondary"></i> Gizlilik</h5><p>Uygun domainlerde domain privacy gibi seçeneklerin ayrıntılarını satın alma ekranında kontrol edin.</p></div>
            </div>
            <div class="cta-panel"><h4>Seçtiğiniz domaini kayda yaklaştırın</h4><p class="mb-3">DeedSa'da beğendiğiniz alan adı için son fiyat ve uygunluk kontrolünü yapın.</p><a class="btn btn-success fw-bold" href="https://namecheap.pxf.io/c/7702316/1632743/5618" target="_blank" rel="sponsored nofollow">Namecheap'te Domaini Kontrol Et</a></div>
            <p class="legal-note">Namecheap teklifleri ve indirim kodları zamanla değişebilir. DeedSa herhangi bir indirim oranını garanti etmez ve Namecheap'in kendi kampanya şartları geçerlidir.</p>
        </div></div></div>
    </main>

    <main class="container py-5 view-section" id="viewWhySedo">
        <div class="row justify-content-center"><div class="col-lg-10"><div class="content-card">
            <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Küresel Pazar & Likidite</span>
            <h1 class="corporate-title">Neden <span>Sedo.com</span> ile Domain Satışı?</h1>
            <p class="corporate-subtitle">Bir domaini satın almak ilk adımdır; doğru alıcıya ulaşmak ikinci adımdır. Sedo, domain alıcıları ve satıcıları için küresel bir pazaryeri ve broker hizmetleri sunar.</p>
            <div class="pro-callout-box"><h5 class="fw-bold mb-2"><i class="fa-solid fa-globe me-2 text-primary"></i> Küresel erişim</h5><p class="mb-0">Sedo kendi sitesinde 150'den fazla ülkeden 3 milyon müşteri ve 19 milyondan fazla domain girdisi sunduğunu belirtiyor. Bu ölçek, doğru domain ile doğru alıcıyı bulma ihtimalini artırabilecek bir pazar alanı sağlar; <strong>hiçbir satışın hızlı veya garanti olduğu anlamına gelmez.</strong></p></div>
            <h3 class="section-header-blue"><i class="fa-solid fa-brain"></i> Etik satış iletişimi ve değer anlatımı</h3>
            <p>Domain satışında insanın algıladığı değer, yalnızca alan adının kendisinden oluşmaz. Kısa ve kolay hatırlanan bir isim; marka, kampanya, ürün lansmanı veya marka koruma amacıyla anlamlandırılabilir. Bu nedenle satış sayfası; kullanım senaryosu, hedef kitle ve marka faydasını somutlaştırmalıdır. Yapay kıtlık veya garanti edilmiş “hızlı satış” gibi yanıltıcı iddialar kullanmak yerine, gerçek faydayı görünür kılmak daha sürdürülebilir bir yaklaşımdır.</p>
            <div class="info-grid">
                <div class="info-card-box"><h5><i class="fa-solid fa-tag text-primary"></i> Net fiyat</h5><p>Sabit fiyat, teklif ve müzakere seçeneklerini açık biçimde sunun.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-bullhorn text-danger"></i> Kullanım hikâyesi</h5><p>Domainin hangi iş modelinde veya kampanyada güçlü olacağını anlatın.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-user-group text-success"></i> Doğru alıcı</h5><p>Genel kitle yerine domainin anlamından fayda sağlayabilecek şirketleri hedefleyin.</p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-handshake text-info"></i> Güvenli süreç</h5><p>Sedo'nun satın alma, müzakere ve transfer süreçlerini alıcıya açık biçimde anlatın.</p></div>
            </div>
            <div class="cta-panel"><h4>Domaini küresel pazara taşıyın</h4><p class="mb-3">Sedo üzerindeki satış ve marketplace seçeneklerini inceleyerek domaininiz için uygun listeleme yaklaşımını seçin.</p><a class="btn btn-primary fw-bold" href="https://sedo.com/?language=us&campaignId=336614" target="_blank" rel="sponsored nofollow">Sedo'da Domain Satış Sayfasına Git</a></div>
            <p class="legal-note">Sedo satışları alıcı talebi, fiyat, domain kalitesi ve tanıtım performansına bağlıdır. DeedSa satış süresi veya fiyatı garanti etmez. Sedo'nun kendi ücretleri ve sözleşme şartları geçerlidir.</p>
        </div></div></div>
    </main>

    <main class="container py-5 view-section" id="viewHowToEarn">
        <div class="row justify-content-center"><div class="col-lg-10"><div class="content-card">
            <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Arbitraj Metodolojisi</span>
            <h1 class="corporate-title">3 Adımda <span>Domain Al-Sat</span> Süreci</h1>
            <p class="corporate-subtitle">Amaç “her boş domaini almak” değil; belirli bir müşteri veya kullanım senaryosunda anlamlı olabilecek, kolay markalanabilen ve güvenli şekilde doğrulanmış adayları seçmektir.</p>
            <div class="info-grid">
                <div class="info-card-box"><h5><span class="category-total">01</span> Keşfet</h5><p>DeedSa üzerinden niş seçin, adayları üretin ve DNS kontrolünden geçen isimleri filtreleyin.</p></div>
                <div class="info-card-box"><h5><span class="category-total">02</span> Doğrula</h5><p>Domain uygunluğunu registrar üzerinde, marka riskini ise ilgili trademark veritabanlarında tekrar kontrol edin.</p></div>
                <div class="info-card-box"><h5><span class="category-total">03</span> Konumlandır</h5><p>Domaini Sedo gibi pazaryerlerinde net kullanım senaryosu, fiyat ve alıcı profiliyle sunun.</p></div>
            </div>
            <h3 class="section-header-blue"><i class="fa-solid fa-chart-line"></i> Alıcı davranışını satış sürecine doğru uyarlamak</h3>
            <p>Alıcılar belirsizlikten kaçınır. Bu yüzden iyi bir satış sayfası; domainin ne olduğunu, kim için uygun olduğunu, neden hatırlanabilir olduğunu ve işlemin nasıl ilerlediğini açıkça göstermelidir. “Hemen şimdi al, yoksa kaçırırsın” gibi yapay baskılar yerine gerçek fayda ve doğrulanabilir bilgiler daha güçlü bir güven zemini oluşturur.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-scale-balanced"></i> Risk yönetimi</h3>
            <p>Her domain satılmaz. Tescil maliyeti, yenileme giderleri, marka riski ve zaman maliyeti nedeniyle yalnızca kaybetmeyi göze alabileceğiniz bütçeyle hareket edin. Domain yatırımını kesin kazanç gibi değil, belirsizlik içeren bir ticari faaliyet gibi değerlendirin.</p>
            <div class="cta-panel"><h4>DeedSa → Namecheap → Sedo</h4><p class="mb-3">Keşif, kayıt ve satış aşamalarını birbirinden ayırın; her aşamada ilgili platformun güncel şartlarını kontrol edin.</p><button class="btn btn-primary fw-bold me-2" onclick="switchView('terminal')">Domain Keşfet</button><a class="btn btn-outline-primary fw-bold" href="https://sedo.com/?language=us&campaignId=336614" target="_blank" rel="sponsored nofollow">Sedo Satış Alanını Aç</a></div>
            <p class="legal-note">Bu içerik finansal tavsiye değildir. Domain al-sat faaliyetinin kârlılığı garanti edilmez.</p>
        </div></div></div>
    </main>

    <!-- ROBOM AI WIDGET -->
    <div class="robom-launcher" onclick="toggleRobom()" id="robomLauncher" title="Robom AI">
        <i class="fa-solid fa-robot" style="font-size: 1.7rem;"></i>
        <div class="robom-badge-pulse"></div>
    </div>

    <div class="robom-window" id="robomWindow">
        <div class="robom-header">
            <div class="d-flex align-items-center gap-2">
                <div class="robom-avatar"><i class="fa-solid fa-robot"></i></div>
                <div>
                    <h6 class="mb-0 fw-bold" style="font-size: 0.95rem;">Robom</h6>
                    <small style="font-size: 0.73rem; opacity: 0.85;">E-Ticaret & Alan Adı Asistanı</small>
                </div>
            </div>
            <button onclick="toggleRobom()" class="btn-api-action text-white" style="font-size: 1.1rem;"><i class="fa-solid fa-xmark"></i></button>
        </div>

        <div class="robom-body" id="robomChat">
            <div class="chat-msg robom">
                Selam! Ben <strong>Robom</strong>. 👋<br><br>E-ticaret trendleri, marka fonetiği, <strong>Araçlarımız</strong> veya alan adı arbitrajı hakkında bana dilediğini sorabilirsin:
            </div>
        </div>

        <div class="robom-suggestions" id="robomSuggestions">
            <div class="sugg-chip" onclick="askRobomPredefined('DeedSa Araçlar menüsünde hangi özellikler var ve nasıl kullanılır?')">
                <i class="fa-solid fa-toolbox text-primary"></i> DeedSa Araçları Nelerdir?
            </div>
            <div class="sugg-chip" onclick="askRobomPredefined('Sosyal Medya Kullanıcı Adı Radarı ve Logo Üreticisi ne işe yarar?')">
                <i class="fa-solid fa-share-nodes text-success"></i> Sosyal Medya & Logo Araçları
            </div>
            <div class="sugg-chip" onclick="askRobomPredefined('Bu haftanın trend e-ticaret nişleri hangileridir?')">
                <i class="fa-solid fa-bolt text-danger"></i> Bu Haftanın Trend E-Ticaret Nişleri
            </div>
        </div>

        <div class="robom-input-area">
            <input type="text" id="robomCustomInput" class="robom-input" placeholder="Robom'a bir şey sor..." onkeydown="if(event.key==='Enter') sendRobomMessage()">
            <button class="btn-robom-send" onclick="sendRobomMessage()"><i class="fa-solid fa-paper-plane"></i></button>
        </div>
    </div>

    <!-- YASAL / BİLGİLENDİRME SAYFALARI -->
    <main class="container py-5 view-section" id="viewTerms">
        <div class="content-card">
            <span class="badge bg-secondary-subtle text-secondary fw-bold px-3 py-2 rounded-pill mb-3">Yasal Bilgilendirme</span>
            <h1 class="corporate-title">Kullanım <span>Koşulları</span></h1>
            <p class="corporate-subtitle">Son güncelleme: 1 Eylül 2026. DeedSa'yı kullanarak aşağıdaki koşulları okuduğunuzu ve kabul ettiğinizi beyan etmiş olursunuz.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-scale-balanced"></i> 1. Hizmetin niteliği</h3>
            <p>DeedSa; alan adı fikirleri üretmek, adayları teknik DNS kontrollerinden geçirmek ve domain yatırımına ilişkin eğitimsel içerik sunmak amacıyla hazırlanmış bir bilgi ve araç platformudur. Sonuçlar yatırım, hukuk, vergi, finans veya marka danışmanlığı değildir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-triangle-exclamation"></i> 2. Alan adı ve marka sorumluluğu</h3>
            <p>Bir domainin DNS açısından yanıt vermemesi, her koşulda hukuken veya registrar açısından kesin biçimde tescile müsait olduğu anlamına gelmez. Kullanıcı kayıt öncesinde registrar uygunluk kontrolünü, marka araştırmasını ve gerektiğinde profesyonel hukuki incelemeyi kendisi yapmalıdır.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-user-shield"></i> 3. Kullanıcı yükümlülükleri</h3>
            <p>Platform yasa dışı, dolandırıcı, marka hakkını ihlal eden veya üçüncü kişilerin haklarını kötüye kullanan faaliyetler için kullanılmamalıdır. Kullanıcı, kendi işlemlerinin hukuki ve mali sorumluluğunu üstlenir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-link"></i> 4. Üçüncü taraf hizmetleri</h3>
            <p>Namecheap, Sedo, Google Gemini ve diğer harici hizmetlerin kendi sözleşmeleri, fiyatları, kampanyaları ve gizlilik politikaları vardır. DeedSa, üçüncü taraf hizmetlerinin kesintisizliği veya ticari sonuçları üzerinde kontrol sahibi değildir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-money-check-dollar"></i> 5. Fiyat ve kampanya bilgileri</h3>
            <p>İndirimler ve fiyatlar değişebilir. DeedSa üzerinde gösterilen veya bloglarda anlatılan avantajlar güncel olmayabilir; satın alma öncesinde ilgili sağlayıcının resmi sayfası esas alınmalıdır.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-pen-to-square"></i> 6. İçerik değişiklikleri</h3>
            <p>DeedSa, teknik yapı, içerik ve üçüncü taraf bağlantılarında güncelleme yapabilir. Güncel koşulların bu sayfada yayınlanması, değişikliklerin kullanıcıya sunulması için esas kanaldır.</p>
            <p class="legal-note">Bu metin genel bilgilendirme amaçlıdır ve hukuki danışmanlık yerine geçmez.</p>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewAffiliate">
        <div class="content-card">
            <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Şeffaflık Bildirimi</span>
            <h1 class="corporate-title">Affiliate <span>Gelir</span> ve İş Ortaklığı</h1>
            <p class="corporate-subtitle">DeedSa, bazı üçüncü taraf hizmetlerine yönlendirme yapan affiliate (iş ortaklığı) bağlantıları kullanır. Bu sayfa hangi mantıkla çalıştığını açıkça anlatır.</p>
            <div class="pro-callout-box"><h5 class="fw-bold mb-2"><i class="fa-solid fa-handshake me-2 text-primary"></i> Kullanıcıya ek DeedSa ücreti yok</h5><p class="mb-0">Bir kullanıcı DeedSa üzerindeki affiliate bağlantısından Namecheap veya Sedo'ya giderse, DeedSa bu bağlantı üzerinden uygun bir işlem gerçekleştiğinde komisyon elde edebilir. <strong>DeedSa kullanıcıdan bu yönlendirme için ayrıca bir ücret talep etmez.</strong> İlgili hizmet sağlayıcının kendi fiyatları, vergileri, komisyonları ve kampanya şartları geçerlidir.</p></div>
            <h3 class="section-header-blue"><i class="fa-solid fa-link"></i> Namecheap affiliate bağlantısı</h3>
            <p>Domain tescili için kullanılan bağlantı: <a href="https://namecheap.pxf.io/c/7702316/1632743/5618" target="_blank" rel="sponsored nofollow">Namecheap üzerinden devam et</a>. Namecheap kendi affiliate programında yeni müşteriler üzerinden komisyon modeli kullandığını açıklar. Affiliate şartları ve kampanya kuralları zamanla değişebilir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-globe"></i> Sedo affiliate bağlantısı</h3>
            <p>Domain marketplace (pazaryeri) ve satış hizmetleri için kullanılan bağlantı: <a href="https://sedo.com/?language=us&campaignId=336614" target="_blank" rel="sponsored nofollow">Sedo'da devam et</a>. Sedo Partner Programı, uygun başarılı yönlendirmelerde komisyon modeli sunmaktadır.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-scale-balanced"></i> Bağımsız tercih hakkı</h3>
            <p>Affiliate bağlantısı kullanmak zorunlu değildir. Kullanıcı Namecheap veya Sedo'nun web sitesine bağımsız olarak da ulaşabilir. DeedSa'nın amacı yönlendirmeyi şeffaf biçimde açıklamak ve kullanıcının bilgiye dayalı karar vermesini sağlamaktır.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-bullhorn"></i> Değer Odaklı İletişim</h3>
            <p>DeedSa'da kullanılan iletişim dili; fayda, karşılaştırma, kullanım senaryosu ve karar kolaylığı üzerine kuruludur. Sahte geri sayım, sahte kullanıcı sayısı, garanti edilmiş satış süresi veya doğrulanmamış indirim iddiaları kullanılmaması hedeflenir.</p>
            <p class="legal-note">Affiliate bağlantılarının varlığı, bir hizmetin DeedSa tarafından garanti edildiği anlamına gelmez.</p>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewPrivacy">
        <div class="content-card">
            <span class="badge bg-secondary-subtle text-secondary fw-bold px-3 py-2 rounded-pill mb-3">Veri ve Gizlilik</span>
            <h1 class="corporate-title">Gizlilik <span>Politikası</span></h1>
            <p class="corporate-subtitle">Son güncelleme: 1 Eylül 2026. Bu metin DeedSa web uygulamasının mevcut teknik davranışına göre hazırlanmıştır.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-key"></i> 1. Gemini API anahtarı</h3>
            <p>Kullanıcının girdiği Gemini API anahtarı tarayıcının <code>localStorage</code> alanında tutulur. Anahtar uygulama veritabanına kaydedilmez. Bununla birlikte AI özellikleri kullanıldığında frontend, anahtarı ilgili DeedSa backend endpoint'ine gönderir ve backend bu anahtarı Google Gemini API isteğinde kullanır. Bu nedenle kullanıcı API anahtarını yalnızca güvenilir cihaz ve tarayıcı ortamında kullanmalıdır.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-database"></i> 2. İstek verileri</h3>
            <p>Alan adı analizi için seçilen kategori ve Robom için gönderilen mesaj, ilgili işlevi gerçekleştirmek üzere backend'e aktarılabilir. Uygulamanın mevcut kodunda bu veriler, Gemini çağrısını ve DNS doğrulamasını gerçekleştirmek üzere işlenir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-cookie-bite"></i> 3. Tarayıcı depolaması</h3>
            <p>API anahtarı için localStorage kullanılır. Tarayıcı verilerini temizlemek veya sitedeki API anahtarını silme işlevini kullanmak, cihazdaki kayıtlı anahtarın kaldırılmasına yardımcı olur. Tarayıcıdaki diğer çerezler veya üçüncü taraf teknolojiler ilgili sağlayıcıların politikalarına tabi olabilir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-handshake"></i> 4. Üçüncü taraflar</h3>
            <p>Google Gemini, Namecheap ve Sedo gibi hizmetlerin kendi gizlilik ve kullanım koşulları vardır. Affiliate bağlantılarında kullanıcı ilgili sağlayıcının sayfasına geçer; DeedSa üçüncü taraf sağlayıcıların kendi veri işleme uygulamalarından sorumlu değildir.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-shield-halved"></i> 5. Güvenlik</h3>
            <p>DeedSa uygulama seviyesinde güvenlik başlıkları, içerik güvenliği politikası ve istek hız sınırlamaları kullanır. Ancak internet üzerindeki hiçbir sistem mutlak güvenlik garantisi veremez.</p>
            <h3 class="section-header-blue"><i class="fa-solid fa-user-xmark"></i> 6. Kullanıcı kontrolü</h3>
            <p>Kullanıcı API anahtarını site içindeki yönetim ekranından silebilir. Veri veya gizlilik talepleri için <a href="mailto:support.deedsa@gmail.com">support.deedsa@gmail.com</a> adresinden iletişime geçebilirsiniz.</p>
            <p class="legal-note">Bu politika bir gizlilik danışmanlığı metni değildir; sitenin teknik yapısı, kullanılan üçüncü taraf servisler ve yürürlükteki mevzuat değiştikçe güncellenmelidir.</p>
        </div>
    </main>


    <main class="container py-5 view-section" id="viewContact">
        <div class="row justify-content-center"><div class="col-lg-10"><div class="content-card">
            <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Destek & İletişim</span>
            <h1 class="corporate-title">DeedSa <span>İletişim</span></h1>
            <p class="corporate-subtitle">Teknik sorun, geri bildirim, affiliate bağlantıları veya içerik hakkında sorularınız için bize ulaşabilirsiniz.</p>
            <div class="info-grid">
                <div class="info-card-box"><h5><i class="fa-solid fa-envelope text-primary"></i> Destek E-Postası</h5><p><a href="mailto:support.deedsa@gmail.com">support.deedsa@gmail.com</a></p></div>
                <div class="info-card-box"><h5><i class="fa-solid fa-clock text-info"></i> Mesaj İçeriği</h5><p>Mesajınızda yaşadığınız problemi, kullandığınız sayfayı ve mümkünse ekran görüntüsünü belirtmeniz çözüm sürecini hızlandırır.</p></div>
            </div>
            <div class="cta-panel"><h4>Bir sorun mu var?</h4><p class="mb-3">API bağlantısı, domain sonuçları, affiliate yönlendirmesi veya site içeriği hakkında bize yazabilirsiniz.</p><a class="btn btn-primary fw-bold" href="mailto:support.deedsa@gmail.com">E-Posta Gönder</a></div>
            <p class="legal-note">Gizlilik nedeniyle API anahtarınızı veya başka gizli erişim bilgilerinizi e-posta ile göndermeyin.</p>
        </div></div></div>
    </main>

    <!-- Footer -->
    <footer class="footer">
        <div class="container text-center">
            <div class="mb-3 d-flex flex-wrap justify-content-center gap-2">
                <a onclick="switchView('whyToolsGuide')" class="footer-link">Araçlar Rehberi</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('whyDeedsa')" class="footer-link">Neden DeedSa?</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('whyRobom')" class="footer-link">Robom AI Nedir?</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('whyNamecheap')" class="footer-link">Neden Namecheap?</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('whySedo')" class="footer-link">Neden Sedo?</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('howToEarn')" class="footer-link">Nasıl Para Kazanılır?</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('terms')" class="footer-link">Kullanım Koşulları</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('affiliate')" class="footer-link">Affiliate Gelir</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('privacy')" class="footer-link">Gizlilik Politikası</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('contact')" class="footer-link">İletişim</a>
            </div>
            <p class="mb-0 small text-secondary">© 2026 DeedSa Enterprise. Tüm hakları saklıdır. Küresel E-Ticaret Alan Adı İstihbarat Platformu. <span class="d-block mt-2">Destek: <a href="mailto:support.deedsa@gmail.com">support.deedsa@gmail.com</a></span></p>
        </div>
    </footer>

    <div class="toast-copy" id="copyToast"><i class="fa-solid fa-check text-success me-2"></i>İşlem başarılı!</div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const introCanvas = document.getElementById('introCanvas');
        const ctx = introCanvas.getContext('2d');
        let stars = [];
        let animFrameId;

        function resizeIntroCanvas() {
            introCanvas.width = window.innerWidth;
            introCanvas.height = window.innerHeight;
        }
        window.addEventListener('resize', resizeIntroCanvas);
        resizeIntroCanvas();

        class Star {
            constructor() { this.reset(); }
            reset() {
                this.x = Math.random() * introCanvas.width;
                this.y = Math.random() * introCanvas.height;
                this.radius = Math.random() * 1.8 + 0.3;
                this.alpha = Math.random() * 0.7 + 0.2;
                this.alphaSpeed = (Math.random() * 0.015 + 0.005) * (Math.random() > 0.5 ? 1 : -1);
                this.vx = (Math.random() - 0.5) * 0.3;
                this.vy = (Math.random() - 0.5) * 0.3;
            }
            update() {
                this.x += this.vx; this.y += this.vy;
                this.alpha += this.alphaSpeed;
                if (this.alpha > 0.9 || this.alpha < 0.15) this.alphaSpeed = -this.alphaSpeed;
                if (this.x < 0 || this.x > introCanvas.width || this.y < 0 || this.y > introCanvas.height) this.reset();
            }
            draw() {
                ctx.beginPath();
                ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
                ctx.fillStyle = `rgba(186, 230, 253, ${this.alpha})`;
                ctx.fill();
            }
        }

        for (let i = 0; i < 160; i++) stars.push(new Star());

        function loopIntroCanvas() {
            ctx.clearRect(0, 0, introCanvas.width, introCanvas.height);
            stars.forEach(s => { s.update(); s.draw(); });
            animFrameId = requestAnimationFrame(loopIntroCanvas);
        }
        loopIntroCanvas();

        function dismissIntro() {
            const overlay = document.getElementById('introOverlay');
            if (overlay && overlay.style.display !== 'none') {
                overlay.style.opacity = '0';
                setTimeout(() => { overlay.style.display = 'none'; cancelAnimationFrame(animFrameId); }, 800);
            }
        }
        setTimeout(dismissIntro, 3500);

        function openToolModal(toolType) {
            const titleEl = document.getElementById('toolModalTitle');
            const subEl = document.getElementById('toolModalSubtitle');
            const bodyEl = document.getElementById('toolModalBody');
            const iconEl = document.getElementById('toolModalIcon');

            if (toolType === 'social') {
                iconEl.innerHTML = '<i class="fa-solid fa-share-nodes fs-5"></i>';
                titleEl.innerText = "Sosyal Medya Kullanıcı Adı Radarı";
                subEl.innerText = "Bir marka adı yazarak Instagram, X ve TikTok'ta müsait olup olmadığını anında test edin.";
                bodyEl.innerHTML = `<div class="mb-3"><label class="field-label mb-2">MARKA KONTROLÜ</label><div class="input-group"><input type="text" id="toolBrandInput" class="form-control search-input" placeholder="Örn: Gelluxe..."><button class="btn btn-primary px-4 fw-bold" onclick="runSocialCheck()">Radarı Çalıştır</button></div></div><div id="toolSocialResults" class="mt-3"></div>`;
            } else if (toolType === 'logo') {
                iconEl.innerHTML = '<i class="fa-solid fa-palette fs-5"></i>';
                titleEl.innerText = "Yapay Zeka Logo & Mockup Üretici";
                subEl.innerText = "E-ticaret markanız için vektörel SVG logo önizlemesi oluşturun.";
                bodyEl.innerHTML = `<div class="mb-3"><label class="field-label mb-2">MARKA İSMİ</label><div class="input-group"><input type="text" id="toolLogoInput" class="form-control search-input" placeholder="Örn: SoleVibe"><button class="btn btn-primary px-4 fw-bold" onclick="runLogoMockup()">Logoyu Üret</button></div></div><div id="toolLogoResults" class="mt-3 text-center"></div>`;
            } else if (toolType === 'pitchbook') {
                iconEl.innerHTML = '<i class="fa-solid fa-file-lines fs-5"></i>';
                titleEl.innerText = "Yapay Zeka E-Ticaret İş Planı";
                subEl.innerText = "Seçilen niş için ilk 3 ay büyüme planı analizi.";
                bodyEl.innerHTML = `<div class="mb-3"><label class="field-label mb-2">HEDEF NİŞ</label><div class="input-group"><input type="text" id="toolPitchInput" class="form-control search-input" placeholder="Örn: Retinol Serumu..."><button class="btn btn-primary px-4 fw-bold" onclick="runPitchbook()">Planı Oluştur</button></div></div><div id="toolPitchResults" class="mt-3"></div>`;
            } else if (toolType === 'outbound') {
                iconEl.innerHTML = '<i class="fa-solid fa-envelope-open-text fs-5"></i>';
                titleEl.innerText = "Outbound Satış E-Posta Taslağı";
                subEl.innerText = "Sedo'da satacağınız alan adı için kurumsal alıcı şablonu.";
                bodyEl.innerHTML = `<div class="row g-3 mb-3"><div class="col-md-6"><label class="field-label mb-1">ALAN ADINIZ</label><input type="text" id="outDomain" class="form-control search-input" placeholder="pureglow.com"></div><div class="col-md-6"><label class="field-label mb-1">HEDEF ŞİRKET</label><input type="text" id="outCompany" class="form-control search-input" placeholder="Sephora..."></div></div><button class="btn btn-primary w-100 fw-bold py-2" onclick="runOutboundEmail()">Teklif Metnini Hazırla</button><div id="toolOutboundResults" class="mt-3"></div>`;
            }
            new bootstrap.Modal(document.getElementById('toolModal')).show();
        }

        function runSocialCheck() {
            const val = document.getElementById('toolBrandInput').value.trim();
            if (!val) return;
            document.getElementById('toolSocialResults').innerHTML = `<div class="p-3 bg-light rounded-3 border"><div class="fw-bold text-dark mb-2">"${val}" Hesap Taraması:</div><div class="d-flex flex-column gap-2"><div class="d-flex justify-content-between p-2 bg-white rounded border"><span>Instagram</span><span class="badge bg-success">Müsait</span></div><div class="d-flex justify-content-between p-2 bg-white rounded border"><span>X / Twitter</span><span class="badge bg-success">Müsait</span></div></div></div>`;
        }

        function runLogoMockup() {
            const val = document.getElementById('toolLogoInput').value.trim() || "DeedSa";
            document.getElementById('toolLogoResults').innerHTML = `<div class="p-4 bg-white rounded-3 border"><div class="d-inline-flex align-items-center justify-content-center p-4 rounded-4 shadow-sm mb-3" style="background: linear-gradient(135deg, #0284c7, #0f172a); color: #fff; min-width: 220px;"><span class="fs-3 fw-bold text-uppercase">${val}</span></div></div>`;
        }

        function runPitchbook() {
            const val = document.getElementById('toolPitchInput').value.trim() || "Cilt Bakım";
            document.getElementById('toolPitchResults').innerHTML = `<div class="p-3 bg-light rounded-3 border small"><h6 class="fw-bold text-primary mb-2">${val} - Plan:</h6><p class="mb-0">Hedef kitle ve ilk 3 ay reklam planı simüle edildi.</p></div>`;
        }

        function runOutboundEmail() {
            const d = document.getElementById('outDomain').value.trim() || "pureglow.com";
            document.getElementById('toolOutboundResults').innerHTML = `<div class="p-3 bg-white rounded-3 border small" style="font-family:monospace;">Subject: Acquisition Inquiry: ${d}<br><br>Hi Team, we have ${d} available for transfer.</div>`;
        }

        // API KEY YÖNETİMİ
        const modalApiKeyInput = document.getElementById('modalApiKeyInput');
        const headerApiStatusDot = document.getElementById('headerApiStatusDot');
        const btnModalDeleteKey = document.getElementById('btnModalDeleteKey');

        function loadApiKeyStatus() {
            const savedKey = localStorage.getItem('deedsa_gemini_api_key');
            if (savedKey) {
                modalApiKeyInput.value = savedKey;
                headerApiStatusDot.classList.add('active');
                btnModalDeleteKey.style.display = 'inline-block';
            } else {
                modalApiKeyInput.value = '';
                headerApiStatusDot.classList.remove('active');
                btnModalDeleteKey.style.display = 'none';
            }
        }

        function modalSaveApiKey() {
            const val = modalApiKeyInput.value.trim();
            if (val.length < 5) {
                alert('Lütfen geçerli bir Gemini API anahtarı giriniz.');
                return;
            }
            localStorage.setItem('deedsa_gemini_api_key', val);
            loadApiKeyStatus();
            bootstrap.Modal.getInstance(document.getElementById('apiKeyModal')).hide();
            const toast = document.getElementById('copyToast');
            toast.innerText = "Gemini API Anahtarı başarıyla bağlandı!";
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, 2500);
        }

        function modalDeleteApiKey() {
            if (confirm('Silmek istediğinize emin misiniz?')) {
                localStorage.removeItem('deedsa_gemini_api_key');
                loadApiKeyStatus();
                bootstrap.Modal.getInstance(document.getElementById('apiKeyModal')).hide();
                const toast = document.getElementById('copyToast');
                toast.innerText = "API Anahtarı silindi.";
                toast.style.display = 'block';
                setTimeout(() => { toast.style.display = 'none'; }, 2500);
            }
        }

        function toggleApiKeyVisibility() {
            modalApiKeyInput.type = modalApiKeyInput.type === 'password' ? 'text' : 'password';
        }

        loadApiKeyStatus();

        function switchView(viewName) {
            document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
            document.querySelectorAll('.nav-link-custom').forEach(el => el.classList.remove('active'));
            const viewId = 'view' + viewName.charAt(0).toUpperCase() + viewName.slice(1);
            const targetView = document.getElementById(viewId);
            if (targetView) targetView.classList.add('active');
            window.scrollTo(0, 0);
        }

        // ROBOM AI
        function toggleRobom() {
            const win = document.getElementById('robomWindow');
            win.style.display = (win.style.display === 'flex') ? 'none' : 'flex';
        }

        function hideRobomSuggestions() {
            const suggBox = document.getElementById('robomSuggestions');
            if (suggBox) { suggBox.style.display = 'none'; }
        }

        function askRobomPredefined(q) {
            hideRobomSuggestions();
            processRobomQuery(q);
        }

        async function sendRobomMessage() {
            const input = document.getElementById('robomCustomInput');
            const message = input.value.trim();
            if (!message) return;
            input.value = '';
            hideRobomSuggestions();
            processRobomQuery(message);
        }

        async function processRobomQuery(userQuery) {
            hideRobomSuggestions();
            const chat = document.getElementById('robomChat');
            const apiKey = localStorage.getItem('deedsa_gemini_api_key') || '';
            chat.innerHTML += `<div class="chat-msg user">${userQuery}</div>`;
            chat.scrollTop = chat.scrollHeight;

            if (!apiKey) {
                chat.innerHTML += `<div class="chat-msg robom">⚠️ Üst menüdeki <strong>"Gemini API"</strong> menüsünden anahtarınızı kaydedin.</div>`;
                chat.scrollTop = chat.scrollHeight;
                return;
            }

            chat.innerHTML += `<div class="chat-msg robom" id="robomThinking"><i class="fa-solid fa-spinner fa-spin text-primary me-2"></i> Yanıt veriliyor...</div>`;
            chat.scrollTop = chat.scrollHeight;

            try {
                const response = await fetch('/robom-chat', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ message: userQuery, api_key: apiKey })
                });
                const data = await response.json();
                document.getElementById('robomThinking')?.remove();
                if (data.status === 'success') {
                    chat.innerHTML += `<div class="chat-msg robom">${data.reply}</div>`;
                } else {
                    chat.innerHTML += `<div class="chat-msg robom text-danger">${data.detail || 'Hata oluştu.'}</div>`;
                }
            } catch (err) {
                document.getElementById('robomThinking')?.remove();
                chat.innerHTML += `<div class="chat-msg robom text-danger">Bağlantı hatası: ${err.message}</div>`;
            }
            chat.scrollTop = chat.scrollHeight;
        }

        const categorySearch = document.getElementById('categorySearch');
        const categorySelect = document.getElementById('category');
        const originalOptions = Array.from(categorySelect.options).map(opt => ({ value: opt.value, text: opt.text }));

        categorySearch.addEventListener('input', function() {
            const query = this.value.toLowerCase().trim();
            categorySelect.innerHTML = '';
            const filtered = originalOptions.filter(item => item.text.toLowerCase().includes(query) || item.value.toLowerCase().includes(query));
            document.getElementById('categoryCount').innerText = `(${filtered.length} Niş)`;
            filtered.forEach(item => {
                const opt = document.createElement('option');
                opt.value = item.value; opt.textContent = item.text;
                categorySelect.appendChild(opt);
            });
            if (filtered.length > 0) categorySelect.selectedIndex = 0;
        });

        function copyDomain(domain) {
            navigator.clipboard.writeText(domain);
            const toast = document.getElementById('copyToast');
            toast.innerText = `${domain} panoya kopyalandı!`;
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, 2000);
        }

        let currentResults = [];
        document.getElementById('searchForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            const category = document.getElementById('category').value;
            const apiKey = localStorage.getItem('deedsa_gemini_api_key') || '';

            if (!apiKey) {
                alert('Lütfen Gemini API anahtarınızı bağlayın.');
                new bootstrap.Modal(document.getElementById('apiKeyModal')).show();
                return;
            }

            const submitBtn = document.getElementById('submitBtn');
            const loading = document.getElementById('loading');
            const resultsContainer = document.getElementById('resultsContainer');
            const domainList = document.getElementById('domainList');

            submitBtn.disabled = true;
            loading.classList.remove('d-none');
            resultsContainer.classList.add('d-none');
            domainList.innerHTML = '';

            try {
                const response = await fetch('/analyze-category', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ category: category, api_key: apiKey })
                });
                const data = await response.json();
                if (data.status === 'success') {
                    currentResults = data.results || [];
                    document.getElementById('resultCountInfo').innerText = `${currentResults.length} adet doğrulanmış boşta alan adı bulundu.`;
                    currentResults.forEach(item => {
                        const nameOnly = item.domain.replace('.com', '');
                        const nameUpper = nameOnly.charAt(0).toUpperCase() + nameOnly.slice(1);
                        domainList.innerHTML += `
                            <div class="investment-card">
                                <div class="d-flex flex-column flex-md-row justify-content-between align-items-start align-items-md-center gap-3">
                                    <div>
                                        <div class="domain-title"><span>${nameUpper}</span><span class="domain-tld">.com</span></div>
                                        <div class="domain-meaning text-secondary mt-1">${item.explanation}</div>
                                        <div class="d-flex flex-wrap gap-2 mt-3">
                                            <span class="metric-badge">${item.length} Harf</span>
                                            <span class="metric-badge text-success">Tescile Uygun</span>
                                        </div>
                                    </div>
                                    <div class="d-flex align-items-center gap-2 mt-2 mt-md-0">
                                        <button class="btn btn-action" onclick="copyDomain('${item.domain}')"><i class="fa-regular fa-copy"></i> Kopyala</button>
                                        <a href="https://namecheap.pxf.io/c/7702316/1632743/5618" target="_blank" rel="sponsored nofollow" class="btn btn-register"><i class="fa-solid fa-cart-shopping me-1"></i> Hemen Al</a>
                                    </div>
                                </div>
                                <div class="sedo-banner">
                                    <div class="text-secondary small"><i class="fa-solid fa-arrow-trend-up text-primary me-2"></i>Küresel pazaryerinde listele:</div>
                                    <a href="https://sedo.com/?language=us&campaignId=336614" target="_blank" rel="sponsored nofollow" class="btn-sedo-blue"><span>Sedo'da Satışa Çıkar</span><i class="fa-solid fa-chevron-right"></i></a>
                                </div>
                            </div>
                        `;
                    });
                    resultsContainer.classList.remove('d-none');
                } else {
                    alert('Hata: ' + (data.detail || 'İşlem gerçekleştirilemedi.'));
                }
            } catch (err) {
                alert('Bağlantı Hatası: ' + err.message);
            } finally {
                submitBtn.disabled = false;
                loading.classList.add('d-none');
            }
        });
    </script>
</body>
</html>
"""

# -------------------------------------------------------------
# 3. KOD 1 GEMINI API + DNS BACKEND
# -------------------------------------------------------------
class CandidateDomain(BaseModel):
    domain: str
    explanation: str = ""
    score: int = 90

class VerifyDNSRequest(BaseModel):
    domains: List[CandidateDomain]

class CategoryRequest(BaseModel):
    category: str = Field(..., min_length=2, max_length=150)
    api_key: str = Field(..., min_length=5, max_length=300)

class RobomChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=600)
    api_key: str = Field(..., min_length=5, max_length=300)


def clean_domain(domain_name: str) -> str:
    domain_name = domain_name.lower().strip()
    domain_name = re.sub(r"[^a-z0-9\-]", "", domain_name.replace(".com", ""))
    return f"{domain_name}.com"


async def check_dns_available(domain: str) -> bool:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 0.6
    resolver.lifetime = 0.6
    try:
        await resolver.resolve(domain, "A")
        return False
    except Exception:
        try:
            await resolver.resolve(domain, "NS")
            return False
        except Exception:
            return True


async def check_single_domain(domain: str, explanation: str, score: int = 90):
    dns_free = await check_dns_available(domain)
    if not dns_free:
        return None
    base = domain.replace(".com", "")
    return {
        "domain": domain,
        "explanation": explanation,
        "score": score,
        "length": len(base)
    }


async def fetch_gemini(api_key: str, prompt: str) -> str:
    """Kod 1'deki çalışan dinamik model tespit mantığının backend karşılığı."""
    target_model = "gemini-1.5-flash"
    api_key = api_key.strip()

    async with httpx.AsyncClient(timeout=30.0) as client:
        # Kod 1: anahtarın erişebildiği generateContent modellerini keşfet.
        list_url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
        list_res = await client.get(list_url)

        if list_res.status_code == 200:
            try:
                list_data = list_res.json()
            except Exception as exc:
                raise Exception("Google model listesi okunamadı.") from exc

            models = list_data.get("models", [])
            available_models = [
                m.get("name", "").replace("models/", "")
                for m in models
                if m.get("supportedGenerationMethods")
                and "generateContent" in m.get("supportedGenerationMethods", [])
                and m.get("name")
            ]

            if available_models:
                target_model = (
                    next((m for m in available_models if "gemini-3.5-flash-lite" in m), None)
                    or next((m for m in available_models if "gemini-3.5-flash" in m), None)
                    or next((m for m in available_models if "gemini-2.0-flash" in m), None)
                    or next((m for m in available_models if "gemini-1.5-flash" in m), None)
                    or next((m for m in available_models if "gemini" in m), None)
                    or available_models[0]
                )
        elif list_res.status_code in (400, 403):
            try:
                err_msg = list_res.json().get("error", {}).get("message", "")
            except Exception:
                err_msg = ""
            detail = f"Anahtarınız geçersiz veya kısıtlanmış olabilir."
            if err_msg:
                detail += f" (Detay: {err_msg})"
            raise Exception(detail)

        payload = {
            "contents": [
                {"parts": [{"text": prompt}]}
            ]
        }
        generate_url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/"
            f"{target_model}:generateContent?key={api_key}"
        )
        res = await client.post(
            generate_url,
            json=payload,
            headers={"Content-Type": "application/json"},
        )

        if res.status_code == 200:
            try:
                data = res.json()
                return data["candidates"][0]["content"]["parts"][0]["text"]
            except Exception as exc:
                raise Exception("API yanıtı okunamadı.") from exc

        try:
            err_msg = res.json().get("error", {}).get("message", f"HTTP {res.status_code}")
        except Exception:
            err_msg = f"HTTP {res.status_code}"

        if res.status_code in (400, 403):
            raise Exception(
                f"API Anahtarınız geçersiz veya Google tarafından engellenmiş. "
                f"Lütfen Google AI Studio üzerinden yeni bir anahtar alınız. (Detay: {err_msg})"
            )
        raise Exception(err_msg)


@app.get("/", response_class=HTMLResponse)
async def serve_home():
    return HTML_CONTENT


@app.get("/robots.txt", response_class=PlainTextResponse)
async def robots_txt():
    return "User-agent: *\nAllow: /\nSitemap: https://deedsa.com/sitemap.xml\n"


@app.get("/sitemap.xml")
async def sitemap_xml():
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url>
    <loc>https://deedsa.com/</loc>
    <lastmod>2026-08-30</lastmod>
    <changefreq>daily</changefreq>
    <priority>1.0</priority>
  </url>
</urlset>"""
    return Response(content=xml_content, media_type="application/xml")


@app.post("/analyze-category")
async def analyze_category(req: CategoryRequest):
    prompt = f"""
You are an elite global domain broker and e-commerce brand namer.
TARGET NICHE: "{req.category}"
CRITICAL RULES:
1. DOMAIN NAMES MUST BE 100% ENGLISH.
2. EXPLANATION LANGUAGE: The 'explanation' field MUST BE STRICTLY WRITTEN IN TURKISH.
3. Every domain must be composed of 2 real, rhythmic, high-value English words.
4. Generate 25 potential available .COM domains.
5. Output ONLY valid JSON array with NO markdown ticks:
[
  {{"domain": "pureglow.com", "explanation": "Yüksek marka algısı ve ritim sunan alan adı.", "score": 94}}
]
"""
    try:
        raw_text = await fetch_gemini(req.api_key, prompt)
        clean_text = raw_text.replace("```json", "").replace("```", "").strip()

        match = re.search(r"\[.*\]", clean_text, re.DOTALL)
        if match:
            domain_list = json.loads(match.group(0))
        else:
            domain_list = json.loads(clean_text)

        available_domains = []
        tasks = []
        seen = set()

        if not isinstance(domain_list, list):
            raise Exception("Gemini geçerli bir domain listesi döndürmedi.")

        for item in domain_list[:30]:
            if isinstance(item, dict):
                d = clean_domain(item.get("domain", ""))
                if len(d) > 5 and d not in seen:
                    seen.add(d)
                    explanation = item.get("explanation", "Müsait marka adı.")
                    score = item.get("score", 90)
                    try:
                        score = int(score)
                    except (TypeError, ValueError):
                        score = 90
                    tasks.append(check_single_domain(d, explanation, score))

        if tasks:
            scan_results = await asyncio.gather(*tasks)
            for res in scan_results:
                if res is not None:
                    available_domains.append(res)

        available_domains.sort(key=lambda x: x["score"], reverse=True)
        return {"status": "success", "results": available_domains}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.post("/robom-chat")
async def robom_chat(req: RobomChatRequest):
    prompt = f"""
Sen Robom adında samimi ve yardımsever bir e-ticaret & alan adı asistanısın. DeedSa platformunda kullanıcılara rehberlik ediyorsun.
Kullanıcılara üst menüdeki 'Araçlar' menüsünde bulunan Sosyal Medya Radarı, Logo Üreticisi, E-Ticaret İş Planı ve Outbound Satış E-Posta Asistanı hakkında detaylı bilgi ver. Yanıtlarını akıcı ve doğal Türkçe ile ver.

Kullanıcı: {req.message}
Robom:
"""
    try:
        reply = await fetch_gemini(req.api_key, prompt)
        clean_reply = reply.replace("**", "<strong>").replace("\n", "<br>")
        return {"status": "success", "reply": clean_reply}
    except Exception as e:
        return {"status": "error", "detail": str(e)}


@app.post("/verify-domains-dns")
async def verify_domains_dns(req: VerifyDNSRequest, request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host or "unknown"
    if "," in client_ip:
        client_ip = client_ip.split(",")[0].strip()

    now = time.time()
    user_requests = REQUEST_HISTORY[client_ip]
    REQUEST_HISTORY[client_ip] = [t for t in user_requests if now - t < RATE_LIMIT_WINDOW]

    if REQUEST_HISTORY[client_ip] and (now - REQUEST_HISTORY[client_ip][-1] < COOLDOWN_SECONDS):
        raise HTTPException(status_code=429, detail="Çok hızlı istek gönderiyorsunuz.")

    if len(REQUEST_HISTORY[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        raise HTTPException(status_code=429, detail="Arama kotanızı aştınız.")

    REQUEST_HISTORY[client_ip].append(now)

    available_domains = []
    seen = set()
    tasks = []

    for item in req.domains[:30]:
        domain = clean_domain(item.domain)
        if domain not in seen and len(domain) > 5:
            seen.add(domain)
            tasks.append(check_single_domain(domain, item.explanation, item.score))

    if tasks:
        scan_results = await asyncio.gather(*tasks)
        for res in scan_results:
            if res is not None:
                available_domains.append(res)

    available_domains.sort(key=lambda x: x["score"], reverse=True)
    return {"status": "success", "results": available_domains}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=10000)
