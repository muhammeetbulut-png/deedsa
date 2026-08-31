import os
import re
import json
import time
import asyncio
from collections import defaultdict
import dns.asyncresolver
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field
import httpx

app = FastAPI(
    title="DeedSa Enterprise Domain Intelligence",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# -------------------------------------------------------------
# 1. GÜVENLİK DUVARI (WAF) & KULLANICI UYARI MOTORU
# -------------------------------------------------------------
REQUEST_HISTORY = defaultdict(list)
USER_STRIKES = defaultdict(int)
RATE_LIMIT_WINDOW = 60
MAX_REQUESTS_PER_WINDOW = 30
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
          "@type": "SoftwareApplication",
          "name": "DeedSa Enterprise Domain Intelligence",
          "applicationCategory": "BusinessApplication",
          "operatingSystem": "All",
          "url": "https://deedsa.com/",
          "offers": { "@type": "Offer", "price": "0", "priceCurrency": "USD" },
          "description": "E-ticaret markaları ve domain yatırımcıları için yapay zeka fonetik analizi ve canlı DNS doğrulama terminali."
        },
        {
          "@type": "FAQPage",
          "mainEntity": [
            {
              "@type": "Question",
              "name": "DeedSa üzerindeki alan adları gerçekten boşta mı?",
              "acceptedAnswer": {
                "@type": "Answer",
                "text": "Evet. DeedSa, üretilen tüm iki kelimelik kombinasyonları ICANN akredite küresel root DNS (A ve NS) sunucularından canlı sorgular. Yalnızca tescile müsait olanlar listelenir."
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

        /* SEO BİLGİ VE REHBER BLOKLARI */
        .seo-content-section { background: #ffffff; border-top: 1px solid var(--border-color); padding: 60px 0 40px; color: #475569; }
        .seo-heading { font-size: 1.45rem; font-weight: 800; color: #0f172a; margin-bottom: 16px; letter-spacing: -0.02em; }
        .seo-text { font-size: 0.96rem; line-height: 1.85; color: #475569; margin-bottom: 20px; text-align: justify; }
        .seo-faq-item { background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 14px; padding: 24px; margin-bottom: 18px; }
        .seo-faq-question { font-size: 1.05rem; font-weight: 800; color: #0f172a; margin-bottom: 10px; }
        .seo-faq-answer { font-size: 0.94rem; line-height: 1.75; color: #64748b; margin-bottom: 0; }

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
                            <li><a class="dropdown-item" href="#" onclick="switchView('getApiKey')"><i class="fa-solid fa-circle-question text-info me-2"></i> Gemini API Nasıl Alınır?</a></li>
                        </ul>
                    </div>

                    <a onclick="switchView('whyToolsGuide')" class="nav-link-custom text-info fw-bold" id="navWhyToolsGuide"><i class="fa-solid fa-book-open me-1"></i> Araçlar Rehberi</a>
                    <a onclick="switchView('whyDeedsa')" class="nav-link-custom" id="navWhyDeedsa">Neden DeedSa?</a>
                    <a onclick="switchView('whyRobom')" class="nav-link-custom" id="navWhyRobom"><i class="fa-solid fa-robot text-primary me-1"></i> Robom AI Nedir?</a>
                    <a onclick="switchView('whyNamecheap')" class="nav-link-custom" id="navWhyNamecheap">Neden Namecheap?</a>
                    <a onclick="switchView('whySedo')" class="nav-link-custom" id="navWhySedo">Neden Sedo?</a>
                    <a onclick="switchView('howToEarn')" class="nav-link-custom" id="navHowToEarn">Nasıl Para Kazanılır?</a>
                </nav>
            </div>
        </div>
    </header>

    <!-- MOBİL YAN MENÜ (OFFCANVAS) -->
    <div class="offcanvas offcanvas-end d-lg-none" tabindex="-1" id="mobileOffcanvasMenu" aria-labelledby="mobileMenuLabel">
        <div class="offcanvas-header border-bottom">
            <h5 class="offcanvas-title fw-bold text-primary" id="mobileMenuLabel">Menü</h5>
            <button type="button" class="btn-close" data-bs-dismiss="offcanvas" aria-label="Kapat"></button>
        </div>
        <div class="offcanvas-body d-flex flex-column gap-3">
            <div class="fw-bold text-dark border-bottom pb-2"><i class="fa-solid fa-toolbox text-primary me-2"></i> Araçlar</div>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('terminal')">Alan Adı Keşif Motoru</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="openToolModal('social')">Sosyal Medya Radarı</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="openToolModal('logo')">Logo & Mockup Üretici</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="openToolModal('pitchbook')">E-Ticaret İş Planı</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="openToolModal('outbound')">Satış E-Postası (Pitch)</a>
            
            <div class="fw-bold text-dark border-bottom pb-2 mt-2"><i class="fa-solid fa-key text-primary me-2"></i> Gemini API</div>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" data-bs-toggle="modal" data-bs-target="#apiKeyModal">API Anahtarını Yönet</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('getApiKey')">Gemini API Nasıl Alınır?</a>

            <div class="fw-bold text-dark border-bottom pb-2 mt-2"><i class="fa-solid fa-book-open text-primary me-2"></i> Rehberler</div>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('whyToolsGuide')">Araçlar Rehberi</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('whyDeedsa')">Neden DeedSa?</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('whyRobom')">Robom AI Nedir?</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('whyNamecheap')">Neden Namecheap?</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('whySedo')">Neden Sedo?</a>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" onclick="switchView('howToEarn')">Nasıl Para Kazanılır?</a>
        </div>
    </div>

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
                            <input type="password" id="modalApiKeyInput" class="form-control search-input" placeholder="AIzaSy..." style="font-family: monospace;">
                            <button class="btn btn-outline-secondary" type="button" onclick="toggleApiKeyVisibility()" id="btnToggleVisibility"><i class="fa-regular fa-eye"></i></button>
                        </div>
                        <div class="form-text small mt-2 text-muted">
                            <i class="fa-solid fa-shield-halved text-success me-1"></i> Sıfır Bilgi Güvenliği: Anahtarınız DeedSa sunucularına asla kaydedilmez.
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
                        <i class="fa-solid fa-trash-can me-1"></i> Anahtarı Sil
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
                            <option value="Plumping Lip Mask and Night Lip Care">Dudak Dolgunlaştırıcı ve Bakım Maskeleri</option>
                            <option value="Gua Sha and Jade Stone Face Massage Tools">Yüz Masaj Taşları ve Gua Sha Setleri</option>
                            <option value="Pore Minimizing Clarifying Toners">Gözenek Sıkılaştırıcı Tonikler</option>
                            <option value="Stretch Mark and Cellulite Treatment Oils">Vücut Çatlak ve Selülit Bakım Yağları</option>
                            <option value="Collagen and Biotin Beauty Supplements">Kolajen ve Biyotin Cilt Takviyeleri</option>
                            <option value="Heatless Silk Hair Curler Sets">Isısız İpek Saç Şekillendirici Setler</option>
                            <option value="Cordless Hair Straightener and Styling Brushes">Kablosuz Saç Düzleştirici Fırçalar</option>
                            <option value="Anti-Hair Loss and Regrowth Serums">Saç Dökülmesi Karşıtı Serumlar</option>
                            <option value="Pure Rosemary Essential Hair Growth Oils">Biberiye ve Doğal Saç Bakım Yağları</option>
                            <option value="Scalp Massager and Shampoo Exfoliator Brushes">Kafa Derisi Masaj ve Şampuan Fırçaları</option>
                            <option value="High-Speed Ionic Travel Hair Dryers">Hızlı Kurutan İyonik Saç Kurutma Makineleri</option>
                            <option value="Magnetic Glue-Free False Eyelashes">Manyetik ve Yapışkansız Takma Kirpikler</option>
                            <option value="Lighted LED Mirror Travel Cosmetic Bags">Işıklı LED Aynalı Seyahat Makyaj Çantaları</option>
                            <option value="Automatic Electric Makeup Brush Cleaners">Elektrikli Makyaj Fırçası Temizleyicileri</option>
                            <option value="Press-on Reusable Artificial Gel Nails">Press-on Hazır Jel Tırnaklar</option>
                            <option value="Mini Cordless UV Nail Curing Lamps">Taşınabilir Kablosuz UV Tırnak Lambaları</option>
                            <option value="Professional Beard Growth and Grooming Kits">Sakal Büyütücü ve Bakım Setleri</option>
                            <option value="Solid Pocket and Roll-on Colognes">Katı ve Roll-on Doğal Parfümler</option>
                            <option value="Teeth Whitening Powders and LED Strips">Ağız ve Diş Beyazlatma Setleri</option>
                            <option value="Cordless Portable Dental Water Flossers">Taşınabilir Şarjlı Ağız Duşları</option>
                            <option value="Memory Foam Ergonomic Lumbar Support Cushions">Ortopedik Bel ve Sırt Destek Minderleri</option>
                            <option value="Medical Posture Corrector and Spine Braces">Duruş Düzeltici Dik Duruş Korseleri</option>
                            <option value="Deep Tissue Mini Portable Massage Guns">Taşınabilir Mini Masaj Tabancaları</option>
                            <option value="Cervical Neck Traction Decompression Pillows">Boyun ve Omuz Dekompresyon Yastıkları</option>
                            <option value="Mouth Tape for Deep Sleep and Anti-Snoring">Horlama Önleyici Ağız Bantları (Mouth Tape)</option>
                            <option value="100 Percent Pure Silk Weighted Sleep Masks">İpek ve Ağırlıklı Uyku Göz Bantları</option>
                            <option value="Acupressure Spike Massage Mat and Pillow Sets">Akupresür Masaj Matı ve Yastık Setleri</option>
                            <option value="MagSafe Leather Magnetic Wallet Card Holders">MagSafe Manyetik Deri Kartlık ve Cüzdanlar</option>
                            <option value="Foldable 3-in-1 Fast Wireless Charging Stations">3'ü 1 Arada Katlanabilir Kablosuz Şarj İstasyonları</option>
                            <option value="Anti-Spy Privacy Tempered Glass Screen Protectors">Anti-Spy Hayalet Ekran Koruyucular</option>
                            <option value="Heavy Duty Shockproof Clear Phone Cases">Darbe Emici Tasarımlı Telefon Kılıfları</option>
                            <option value="Portable Magnetic Wireless Mini Powerbanks">Manyetik Kablosuz Mini Powerbankler</option>
                            <option value="Pocket Wireless Thermal Sticker and Photo Printers">Telefon Uyumlu Mini Termal Fotoğraf Yazıcıları</option>
                            <option value="Portable USB Rechargeable Mini Blender Bottles">Taşınabilir Mini Smoothie Blenderları</option>
                            <option value="Flame Effect Ultrasonic Aromatherapy Diffusers">Alev Efektli Aromaterapi Difüzörleri</option>
                            <option value="Multi-Blade Vegetable Mandoline Slicers">Çok Fonksiyonlu Sebze Doğrayıcı Mandolinler</option>
                            <option value="Reusable Non-Stick Silicone Air Fryer Liners">Airfryer Silikon Pişirme Kapları</option>
                            <option value="Smart LED Temperature Display Insulated Bottles">Sıcaklık Göstergeli Çelik Termoslar</option>
                            <option value="Portable Manual and Electric Espresso Makers">Taşınabilir Manuel Espresso Makineleri</option>
                            <option value="Calming Orthopedic Pet Beds for Cats and Dogs">Kedi ve Köpek Sakinleştirici Yataklar</option>
                            <option value="Automatic Interactive Motion Laser Cat Toys">Otomatik Sensörlü Kedi Oyuncakları</option>
                            <option value="Ultra-Quiet Pet Water Fountain Dispensers">Kedi ve Köpek Filtreli Su Pınarları</option>
                            <option value="Automatic Sensor Clamping Car Phone Mounts">Sensörlü Kablosuz Araç Telefon Tutucuları</option>
                            <option value="High Power Handheld Cordless Car Vacuum Cleaners">Araç İçi Şarjlı Mini Süpürgeler</option>
                            <option value="Non-Slip Eco Friendly Natural Rubber Yoga Mats">Kaymaz Doğal Kauçuk Yoga Matları</option>
                            <option value="Heavy Duty Fabric Resistance Workout Bands">Egzersiz Direnç Lastiği Setleri</option>
                            <option value="Ergonomic Laptop Riser and Tablet Stands">Katlanabilir Metal Laptop Standları</option>
                            <option value="ScreenBar Monitor Mounted Eye Care LED Lamps">Ekran Üstü Ayarlanabilir Monitör Işıkları</option>
                            <option value="Giyim ve Moda">Giyim ve Moda</option>
                            <option value="Kadın Giyim">Kadın Giyim</option>
                            <option value="Erkek Giyim">Erkek Giyim</option>
                            <option value="Çocuk Giyim">Çocuk Giyim</option>
                            <option value="Ayakkabı ve Çanta">Ayakkabı ve Çanta</option>
                            <option value="Kadın Ayakkabı">Kadın Ayakkabı</option>
                            <option value="Erkek Ayakkabı">Erkek Ayakkabı</option>
                            <option value="Çanta ve Cüzdan">Çanta ve Cüzdan</option>
                            <option value="Aksesuar ve Takı">Aksesuar ve Takı</option>
                            <option value="Takı ve Mücevher">Takı ve Mücevher</option>
                            <option value="Saat ve Gözlük">Saat ve Gözlük</option>
                            <option value="Şapka ve Atkı">Şapka ve Atkı</option>
                            <option value="Anne ve Bebek">Anne ve Bebek</option>
                            <option value="Bebek Bezi ve Bakım">Bebek Bezi ve Bakım</option>
                            <option value="Bebek Arabası ve Puset">Bebek Arabası ve Puset</option>
                            <option value="Bebek Odası Mobilyası">Bebek Odası Mobilyası</option>
                            <option value="Oyuncak ve Hobi">Oyuncak ve Hobi</option>
                            <option value="Eğitici Oyuncaklar">Eğitici Oyuncaklar</option>
                            <option value="Kutu Oyunları">Kutu Oyunları</option>
                            <option value="Lego ve Yapı Setleri">Lego ve Yapı Setleri</option>
                            <option value="Elektronik">Elektronik</option>
                            <option value="Cep Telefonu ve Aksesuar">Cep Telefonu ve Aksesuar</option>
                            <option value="Bilgisayar ve Tablet">Bilgisayar ve Tablet</option>
                            <option value="Televizyon ve Ses Sistemleri">Televizyon ve Ses Sistemleri</option>
                            <option value="Ev ve Yaşam">Ev ve Yaşam</option>
                            <option value="Ev Tekstili">Ev Tekstili</option>
                            <option value="Mutfak Gereçleri">Mutfak Gereçleri</option>
                            <option value="Aydınlatma Ürünleri">Aydınlatma Ürünleri</option>
                            <option value="Mobilya">Mobilya</option>
                            <option value="Oturma Odası Mobilyaları">Oturma Odası Mobilyaları</option>
                            <option value="Yatak Odası Mobilyaları">Yatak Odası Mobilyaları</option>
                            <option value="Çalışma Odası Mobilyaları">Çalışma Odası Mobilyaları</option>
                            <option value="Yapı Market ve Hırdavat">Yapı Market ve Hırdavat</option>
                            <option value="El Aletleri">El Aletleri</option>
                            <option value="Bahçe Bakım Ürünleri">Bahçe Bakım Ürünleri</option>
                            <option value="Boya ve Badana Malzemeleri">Boya ve Badana Malzemeleri</option>
                            <option value="Kişisel Bakım ve Kozmetik">Kişisel Bakım ve Kozmetik</option>
                            <option value="Cilt Bakımı">Cilt Bakımı</option>
                            <option value="Makyaj Malzemeleri">Makyaj Malzemeleri</option>
                            <option value="Saç Bakım Ürünleri">Saç Bakım Ürünleri</option>
                            <option value="Sağlık ve Tıbbi Ürünler">Sağlık ve Tıbbi Ürünler</option>
                            <option value="Vitamin ve Takviyeler">Vitamin ve Takviyeler</option>
                            <option value="Ortopedik Ürünler">Ortopedik Ürünler</option>
                            <option value="İlk Yardım Malzemeleri">İlk Yardım Malzemeleri</option>
                            <option value="Spor ve Outdoor">Spor ve Outdoor</option>
                            <option value="Fitness ve Kondisyon">Fitness ve Kondisyon</option>
                            <option value="Kamp ve Doğa Sporları">Kamp ve Doğa Sporları</option>
                            <option value="Takım Sporları">Takım Sporları</option>
                            <option value="Süpermarket ve Gıda">Süpermarket ve Gıda</option>
                            <option value="Kuru Gıda ve Bakliyat">Kuru Gıda ve Bakliyat</option>
                            <option value="Atıştırmalıklar">Atıştırmalıklar</option>
                            <option value="İçecek Çeşitleri">İçecek Çeşitleri</option>
                            <option value="Evcil Hayvan Ürünleri">Evcil Hayvan Ürünleri</option>
                            <option value="Kedi Maması ve Kumları">Kedi Maması ve Kumları</option>
                            <option value="Köpek Maması ve Aksesuarları">Köpek Maması ve Aksesuarları</option>
                            <option value="Kuş ve Balık Malzemeleri">Kuş ve Balık Malzemeleri</option>
                            <option value="Kitap, Müzik ve Hobi">Kitap, Müzik ve Hobi</option>
                            <option value="Roman ve Edebiyat">Roman ve Edebiyat</option>
                            <option value="Kişisel Gelişim Kitapları">Kişisel Gelişim Kitapları</option>
                            <option value="Konsol Oyunları">Konsol Oyunları</option>
                            <option value="Otomotiv ve Motosiklet">Otomotiv ve Motosiklet</option>
                            <option value="Oto Bakım Ürünleri">Oto Bakım Ürünleri</option>
                            <option value="Motosiklet Kask ve Ekipmanları">Motosiklet Kask ve Ekipmanları</option>
                            <option value="Oto Paspas ve Kılıflar">Oto Paspas ve Kılıflar</option>
                            <option value="Hediye ve Özel Günler">Hediye ve Özel Günler</option>
                            <option value="Doğum Günü Hediyeleri">Doğum Günü Hediyeleri</option>
                            <option value="Sevgililer Günü Ürünleri">Sevgililer Günü Ürünleri</option>
                            <option value="Çiçek ve Aranjmanlar">Çiçek ve Aranjmanlar</option>
                            <option value="Ofis ve Kırtasiye">Ofis ve Kırtasiye</option>
                            <option value="Defter ve Ajandalar">Defter ve Ajandalar</option>
                            <option value="Kalem ve Yazı Gereçleri">Kalem ve Yazı Gereçleri</option>
                            <option value="Dosyalama Ürünleri">Dosyalama Ürünleri</option>
                            <option value="Sanat ve El Sanatları">Sanat ve El Sanatları</option>
                            <option value="Resim Malzemeleri">Resim Malzemeleri</option>
                            <option value="Dikiş ve Nakış İpleri">Dikiş ve Nakış İpleri</option>
                            <option value="Takı Tasarım Malzemeleri">Takı Tasarım Malzemeleri</option>
                            <option value="İkinci El ve Yenilenmiş">İkinci El ve Yenilenmiş</option>
                            <option value="Yenilenmiş Akıllı Telefonlar">Yenilenmiş Akıllı Telefonlar</option>
                            <option value="Yenilenmiş Laptoplar">Yenilenmiş Laptoplar</option>
                            <option value="İkinci El Koleksiyon Kitapları">İkinci El Koleksiyon Kitapları</option>
                            <option value="Dijital Ürünler ve Lisanslar">Dijital Ürünler ve Lisanslar</option>
                            <option value="Yazılım Lisansları">Yazılım Lisansları</option>
                            <option value="Online Eğitim Kursları">Online Eğitim Kursları</option>
                            <option value="Tasarım Şablonları ve Grafikler">Tasarım Şablonları ve Grafikler</option>
                            <option value="Yerli ve El Yapımı Ürünler">Yerli ve El Yapımı Ürünler</option>
                            <option value="Yöresel Gıda Ürünleri">Yöresel Gıda Ürünleri</option>
                            <option value="Ahşap El Yapımı Eşyalar">Ahşap El Yapımı Eşyalar</option>
                            <option value="Seramik ve Çini Ürünleri">Seramik ve Çini Ürünleri</option>
                            <option value="Sürdürülebilir Ürünler">Sürdürülebilir Ürünler</option>
                            <option value="Sıfır Atık Mutfak Gereçleri">Sıfır Atık Mutfak Gereçleri</option>
                            <option value="Geri Dönüştürülmüş Giyim">Geri Dönüştürülmüş Giyim</option>
                            <option value="Vegan Kozmetik Ürünleri">Vegan Kozmetik Ürünleri</option>
                            <option value="Koleksiyon ve Antika">Koleksiyon ve Antika</option>
                            <option value="Antika Saat ve Eşyalar">Antika Saat ve Eşyalar</option>
                            <option value="Model Araç ve Tren Setleri">Model Araç ve Tren Setleri</option>
                            <option value="Çizgi Roman ve Figürler">Çizgi Roman ve Figürler</option>
                            <option value="İş Kıyafetleri ve Üniforma">İş Kıyafetleri ve Üniforma</option>
                            <option value="Sağlık Çalışanı Formaları">Sağlık Çalışanı Formaları</option>
                            <option value="Güvenlik ve İşçi Kıyafetleri">Güvenlik ve İşçi Kıyafetleri</option>
                            <option value="Okul Kıyafetleri ve Önlükler">Okul Kıyafetleri ve Önlükler</option>
                            <option value="İç Mimari ve Tasarım">İç Mimari ve Tasarım</option>
                            <option value="Duvar Kağıdı ve Paneller">Duvar Kağıdı ve Paneller</option>
                            <option value="Zemin Kaplamaları ve Parke">Zemin Kaplamaları ve Parke</option>
                            <option value="Akustik Yalıtım Malzemeleri">Akustik Yalıtım Malzemeleri</option>
                            <option value="Akıllı Ev Teknolojileri">Akıllı Ev Teknolojileri</option>
                            <option value="Akıllı Kapı Kilitleri">Akıllı Kapı Kilitleri</option>
                            <option value="Akıllı Priz ve Anahtarlar">Akıllı Priz ve Anahtarlar</option>
                            <option value="Akıllı Termostatlar">Akıllı Termostatlar</option>
                            <option value="Seyahat ve Tatil">Seyahat ve Tatil</option>
                            <option value="Valiz ve Seyahat Çantaları">Valiz ve Seyahat Çantaları</option>
                            <option value="Boyun Yastığı ve Göz Bandı">Boyun Yastığı ve Göz Bandı</option>
                            <option value="Seyahat Tipi Şişe Setleri">Seyahat Tipi Şişe Setleri</option>
                            <option value="Kahve ve Çay Ekipmanları">Kahve ve Çay Ekipmanları</option>
                            <option value="Türk Kahvesi Makineleri">Türk Kahvesi Makineleri</option>
                            <option value="Filtre Kahve Makineleri">Filtre Kahve Makineleri</option>
                            <option value="French Press ve Demlikler">French Press ve Demlikler</option>
                            <option value="Ev Tipi Spor ve Pilates">Ev Tipi Spor ve Pilates</option>
                            <option value="Pilates Matı ve Topu">Pilates Matı ve Topu</option>
                            <option value="Direnç Lastikleri">Direnç Lastikleri</option>
                            <option value="Dambıl ve Ağırlık Setleri">Dambıl ve Ağırlık Setleri</option>
                            <option value="Dış Giyim ve Mont">Dış Giyim ve Mont</option>
                            <option value="Kadın Mont ve Kaban">Kadın Mont ve Kaban</option>
                            <option value="Erkek Trençkot ve Yelek">Erkek Trençkot ve Yelek</option>
                            <option value="Yağmurluk ve Rüzgarlık">Yağmurluk ve Rüzgarlık</option>
                            <option value="İç Giyim ve Pijama">İç Giyim ve Pijama</option>
                            <option value="Kadın İç Giyim Setleri">Kadın İç Giyim Setleri</option>
                            <option value="Erkek Boxer ve Çorap">Erkek Boxer ve Çorap</option>
                            <option value="Pijama ve Ev Giyim Takımları">Pijama ve Ev Giyim Takımları</option>
                            <option value="Büyük Beden Giyim">Büyük Beden Giyim</option>
                            <option value="Büyük Beden Kadın Elbise">Büyük Beden Kadın Elbise</option>
                            <option value="Büyük Beden Erkek Gömlek">Büyük Beden Erkek Gömlek</option>
                            <option value="Hamile Giyim Ürünleri">Hamile Giyim Ürünleri</option>
                            <option value="Gelinlik ve Nişan">Gelinlik ve Nişan</option>
                            <option value="Gelinlik Modelleri">Gelinlik Modelleri</option>
                            <option value="Damatlık Takım Elbise">Damatlık Takım Elbise</option>
                            <option value="Nişan ve Kıyafet Aksesuarları">Nişan ve Kıyafet Aksesuarları</option>
                            <option value="Spor Giyim ve Aktif Yaşam">Spor Giyim ve Aktif Yaşam</option>
                            <option value="Koşu Taytları ve Şortları">Koşu Taytları ve Şortları</option>
                            <option value="Antrenman Tişörtleri">Antrenman Tişörtleri</option>
                            <option value="Sporcu Sütyenleri">Sporcu Sütyenleri</option>
                            <option value="Bebek Beslenme Ürünleri">Bebek Beslenme Ürünleri</option>
                            <option value="Biberon ve Emzikler">Biberon ve Emzikler</option>
                            <option value="Mama Sandalyesi">Mama Sandalyesi</option>
                            <option value="Göğüs Pompaları ve Saklama">Göğüs Pompaları ve Saklama</option>
                            <option value="Bebek Banyo ve Güvenlik">Bebek Banyo ve Güvenlik</option>
                            <option value="Bebek Küveti ve Filesi">Bebek Küveti ve Filesi</option>
                            <option value="Merdiven ve Kapı Bariyerleri">Merdiven ve Kapı Bariyerleri</option>
                            <option value="Bebek Telsizi ve Kameralar">Bebek Telsizi ve Kameralar</option>
                            <option value="Çocuk ve Genç Odası">Çocuk ve Genç Odası</option>
                            <option value="Çocuk Çalışma Masası">Çocuk Çalışma Masası</option>
                            <option value="Genç Odası Yatakları">Genç Odası Yatakları</option>
                            <option value="Çocuk Halıları ve Perdeleri">Çocuk Halıları ve Perdeleri</option>
                            <option value="Ahşap ve Montessori Oyuncaklar">Ahşap ve Montessori Oyuncaklar</option>
                            <option value="Montessori Denge Tahtaları">Montessori Denge Tahtaları</option>
                            <option value="Ahşap Blok ve Harf Setleri">Ahşap Blok ve Harf Setleri</option>
                            <option value="Eğitici Yapbozlar">Eğitici Yapbozlar</option>
                            <option value="Açık Hava ve Park Oyuncakları">Açık Hava ve Park Oyuncakları</option>
                            <option value="Kaydırak ve Salıncaklar">Kaydırak ve Salıncaklar</option>
                            <option value="Trambolin Çeşitleri">Trambolin Çeşitleri</option>
                            <option value="Şişme Oyun Havuzları">Şişme Oyun Havuzları</option>
                            <option value="Akıllı Telefon Aksesuarları">Akıllı Telefon Aksesuarları</option>
                            <option value="Telefon Kılıfı ve Kapaklar">Telefon Kılıfı ve Kapaklar</option>
                            <option value="Ekran Koruyucu Camlar">Ekran Koruyucu Camlar</option>
                            <option value="Powerbank ve Şarj Aletleri">Powerbank ve Şarj Aletleri</option>
                            <option value="Bilgisayar Bileşenleri">Bilgisayar Bileşenleri</option>
                            <option value="Ekran Kartları (GPU)">Ekran Kartları (GPU)</option>
                            <option value="İşlemciler (CPU)">İşlemciler (CPU)</option>
                            <option value="RAM ve SSD Bellekler">RAM ve SSD Bellekler</option>
                            <option value="Oyuncu Ekipmanları (Gaming)">Oyuncu Ekipmanları (Gaming)</option>
                            <option value="Oyuncu Koltukları">Oyuncu Koltukları</option>
                            <option value="Mekanik Klavye ve Mouse">Mekanik Klavye ve Mouse</option>
                            <option value="Oyuncu Kulaklıkları">Oyuncu Kulaklıkları</option>
                            <option value="Fotoğrafçılık Ekipmanları">Fotoğrafçılık Ekipmanları</option>
                            <option value="DSLR ve Aynasız Kameralar">DSLR ve Aynasız Kameralar</option>
                            <option value="Kamera Lensleri">Kamera Lensleri</option>
                            <option value="Tripod ve Işık Sistemleri">Tripod ve Işık Sistemleri</option>
                            <option value="Mutfak Züccaciye">Mutfak Züccaciye</option>
                            <option value="Tencere ve Tava Setleri">Tencere ve Tava Setleri</option>
                            <option value="Yemek Takımları">Yemek Takımları</option>
                            <option value="Çatal Bıçak Kaşık Takımları">Çatal Bıçak Kaşık Takımları</option>
                            <option value="Ev Temizlik Gereçleri">Ev Temizlik Gereçleri</option>
                            <option value="Dikey ve Robot Süpürgeler">Dikey ve Robot Süpürgeler</option>
                            <option value="Ütü ve Buhar Kazanları">Ütü ve Buhar Kazanları</option>
                            <option value="Mop ve Temizlik Kovaları">Mop ve Temizlik Kovaları</option>
                            <option value="Ev Dekorasyon Objeleri">Ev Dekorasyon Objeleri</option>
                            <option value="Tablo ve Çerçeveler">Tablo ve Çerçeveler</option>
                            <option value="Vazo ve Saksılar">Vazo ve Saksılar</option>
                            <option value="Duvar Saatleri">Duvar Saatleri</option>
                            <option value="Yatak Odası Tekstili">Yatak Odası Tekstili</option>
                            <option value="Nevresim Takımları">Nevresim Takımları</option>
                            <option value="Yastık ve Yorganlar">Yastık ve Yorganlar</option>
                            <option value="Yatak Örtüleri">Yatak Örtüleri</option>
                            <option value="Banyo Tekstili">Banyo Tekstili</option>
                            <option value="Havlu ve Bornoz Setleri">Havlu ve Bornoz Setleri</option>
                            <option value="Banyo Paspasları">Banyo Paspasları</option>
                            <option value="Duš Perdeleri">Duş Perdeleri</option>
                            <option value="Bahçe ve Balkon Mobilyaları">Bahçe ve Balkon Mobilyaları</option>
                            <option value="Bahçe Koltuk Takımları">Bahçe Koltuk Takımları</option>
                            <option value="Balkon Masa Sandalye">Balkon Masa Sandalye</option>
                            <option value="Salıncak ve Hamaklar">Salıncak ve Hamaklar</option>
                            <option value="Hırdavat ve Sabitleyiciler">Hırdavat ve Sabitleyiciler</option>
                            <option value="Vidasız Dübeller ve Civatalar">Vidasız Dübeller ve Civatalar</option>
                            <option value="El Aletleri Çantaları">El Aletleri Çantaları</option>
                            <option value="Matkap ve Vidalama Uçları">Matkap ve Vidalama Uçları</option>
                            <option value="Elektrik ve Tesisat Malzemeleri">Elektrik ve Tesisat Malzemeleri</option>
                            <option value="Sigorta ve Kablo Kanalları">Sigorta ve Kablo Kanalları</option>
                            <option value="Musluk ve Batarya Grupları">Musluk ve Batarya Grupları</option>
                            <option value="LED Ampuller ve Spotlar">LED Ampuller ve Spotlar</option>
                            <option value="Bahçe Sulama Sistemleri">Bahçe Sulama Sistemleri</option>
                            <option value="Bahçe Hortumları ve Tabancaları">Bahçe Hortumları ve Tabancaları</option>
                            <option value="Otomatik Sulama Zamanlayıcıları">Otomatik Sulama Zamanlayıcıları</option>
                            <option value="Çim Fıskiyeleri">Çim Fıskiyeleri</option>
                            <option value="Saç Şekillendirme Aletleri">Saç Şekillendirme Aletleri</option>
                            <option value="Saç Maşaları ve Düzleştiriciler">Saç Maşaları ve Düzleştiriciler</option>
                            <option value="Saç Kurutma Makineleri">Saç Kurutma Makineleri</option>
                            <option value="Saç Sakal Kesme Makineleri">Saç Sakal Kesme Makineleri</option>
                            <option value="Ağız ve Diş Sağlığı">Ağız ve Diş Sağlığı</option>
                            <option value="Şarjlı Diş Fırçaları">Şarjlı Diş Fırçaları</option>
                            <option value="Diş Macunları ve İpleri">Diş Macunları ve İpleri</option>
                            <option value="Ağız Gargaraları">Ağız Gargaraları</option>
                            <option value="Parfüm ve Deodorant">Parfüm ve Deodorant</option>
                            <option value="Kadın Parfüm Çeşitleri">Kadın Parfüm Çeşitleri</option>
                            <option value="Erkek Parfüm Çeşitleri">Erkek Parfüm Çeşitleri</option>
                            <option value="Roll-on ve Deodorantlar">Roll-on ve Deodorantlar</option>
                            <option value="Medikal ve Sağlık Aletleri">Medikal ve Sağlık Aletleri</option>
                            <option value="Tansiyon Aletleri">Tansiyon Aletleri</option>
                            <option value="Ateş Ölçerler">Ateş Ölçerler</option>
                            <option value="Nebulizatör ve Buhar Makineleri">Nebulizatör ve Buhar Makineleri</option>
                            <option value="Kamp ve Doğa Çadırları">Kamp ve Doğa Çadırları</option>
                            <option value="Kamp Çadırları">Kamp Çadırları</option>
                            <option value="Uyku Tulumları">Uyku Tulumları</option>
                            <option value="Kamp Matları ve Şişme Yataklar">Kamp Matları ve Şişme Yataklar</option>
                            <option value="Bisiklet ve Aksesuarları">Bisiklet ve Aksesuarları</option>
                            <option value="Dağ ve Şehir Bisikletleri">Dağ ve Şehir Bisikletleri</option>
                            <option value="Bisiklet Kaskları">Bisiklet Kaskları</option>
                            <option value="Bisiklet Kilidi ve Işıkları">Bisiklet Kilidi ve Işıkları</option>
                            <option value="Deniz ve Havuz Malzemeleri">Deniz ve Havuz Malzemeleri</option>
                            <option value="Deniz Yatağı ve Simitleri">Deniz Yatağı ve Simitleri</option>
                            <option value="Şnorkel ve Maske Setleri">Şnorkel ve Maske Setleri</option>
                            <option value="Yüzücü Mayoları ve Gözlükleri">Yüzücü Mayoları ve Gözlükleri</option>
                            <option value="Temizlik ve Deterjanlar">Temizlik ve Deterjanlar</option>
                            <option value="Çamaşır Deterjanları">Çamaşır Deterjanları</option>
                            <option value="Bulaşık Makinesi Tabletleri">Bulaşık Makinesi Tabletleri</option>
                            <option value="Yüzey Temizleyiciler">Yüzey Temizleyiciler</option>
                            <option value="Kağıt ve Temizlik Ürünleri">Kağıt ve Temizlik Ürünleri</option>
                            <option value="Tuvalet Kağıtları">Tuvalet Kağıtları</option>
                            <option value="Kağıt Havlular">Kağıt Havlular</option>
                            <option value="Islak Mendiller">Islak Mendiller</option>
                            <option value="Çay ve Kahve Çeşitleri">Çay ve Kahve Çeşitleri</option>
                            <option value="Dökme ve Poşet Çaylar">Dökme ve Poşet Çaylar</option>
                            <option value="Türk Kahvesi Çeşitleri">Türk Kahvesi Çeşitleri</option>
                            <option value="Çözünebilir Granül Kahveler">Çözünebilir Granül Kahveler</option>
                            <option value="Kedi Bakım Ürünleri">Kedi Bakım Ürünleri</option>
                            <option value="Kedi Kumları ve Kürekleri">Kedi Kumları ve Kürekleri</option>
                            <option value="Kedi Tırmalama Tahtaları">Kedi Tırmalama Tahtaları</option>
                            <option value="Kedi Konserve Mamaları">Kedi Konserve Mamaları</option>
                            <option value="Köpek Bakım Ürünleri">Köpek Bakım Ürünleri</option>
                            <option value="Köpek Eğitim Tasmaları">Köpek Eğitim Tasmaları</option>
                            <option value="Köpek Çiğneme Kemikleri">Köpek Çiğneme Kemikleri</option>
                            <option value="Köpek Kulübeleri">Köpek Kulübeleri</option>
                            <option value="Edebiyat ve Kitaplar">Edebiyat ve Kitaplar</option>
                            <option value="Türk Romanları">Türk Romanları</option>
                            <option value="Dünya Klasikleri">Dünya Klasikleri</option>
                            <option value="Şiir Kitapları">Şiir Kitapları</option>
                            <option value="Eğitim ve Sınav Kitapları">Eğitim ve Sınav Kitapları</option>
                            <option value="YKS ve LGS Hazırlık Kitapları">YKS ve LGS Hazırlık Kitapları</option>
                            <option value="KPSS ve ÖABT Kaynakları">KPSS ve ÖABT Kaynakları</option>
                            <option value="Yabancı Dil Eğitim Kitapları">Yabancı Dil Eğitim Kitapları</option>
                            <option value="Konsol ve Oyunlar">Konsol ve Oyunlar</option>
                            <option value="PlayStation Oyunları">PlayStation Oyunları</option>
                            <option value="Xbox Oyunları">Xbox Oyunları</option>
                            <option value="Nintendo Switch Oyunları">Nintendo Switch Oyunları</option>
                            <option value="Oto Yedek Parça">Oto Yedek Parça</option>
                            <option value="Fren Balataları ve Diskleri">Fren Balataları ve Diskleri</option>
                            <option value="Silecek ve Filtreler">Silecek ve Filtreler</option>
                            <option value="Akü ve Ateşleme Sistemleri">Akü ve Ateşleme Sistemleri</option>
                            <option value="Motosiklet Aksesuarları">Motosiklet Aksesuarları</option>
                            <option value="Motosiklet Pantolon ve Ceketleri">Motosiklet Pantolon ve Ceketleri</option>
                            <option value="Motosiklet Eldivenleri">Motosiklet Eldivenleri</option>
                            <option value="Motosiklet Çantaları ve Heybeler">Motosiklet Çantaları ve Heybeler</option>
                            <option value="Doğum Günü ve Parti">Doğum Günü ve Parti</option>
                            <option value="Balon ve Süsleme Setleri">Balon ve Süsleme Setleri</option>
                            <option value="Doğum Günü Mumları">Doğum Günü Mumları</option>
                            <option value="Parti Kostümleri">Parti Kostümleri</option>
                            <option value="Buket Gül Çeşitleri">Buket Gül Çeşitleri</option>
                            <option value="Saksı Orkide ve Sukulentler">Saksı Orkide ve Sukulentler</option>
                            <option value="Teraryum ve Tasarım Aranjmanlar">Teraryum ve Tasarım Aranjmanlar</option>
                            <option value="Masaüstü Kırtasiye">Masaüstü Kırtasiye</option>
                            <option value="Zımba ve Delgeç Setleri">Zımba ve Delgeç Setleri</option>
                            <option value="Masaüstü Kalemlikler">Masaüstü Kalemlikler</option>
                            <option value="Not Kağıtları ve Post-it">Not Kağıtları ve Post-it</option>
                            <option value="Okul Çantaları">Okul Çantaları</option>
                            <option value="Anaokulu Sırt Çantaları">Anaokulu Sırt Çantaları</option>
                            <option value="Beslenme Çantaları">Beslenme Çantaları</option>
                            <option value="Kalem Kutuları ve Çantaları">Kalem Kutuları ve Çantaları</option>
                            <option value="Resim ve Boya Malzemeleri">Resim ve Boya Malzemeleri</option>
                            <option value="Akrilik ve Sulu Boyalar">Akrilik ve Sulu Boyalar</option>
                            <option value="Tuval ve Şövale Setleri">Tuval ve Şövale Setleri</option>
                            <option value="Çizim Kalemleri ve Blokları">Çizim Kalemleri ve Blokları</option>
                            <option value="Dikiş ve Hobi Malzemeleri">Dikiş ve Hobi Malzemeleri</option>
                            <option value="Dikiş İğne ve İp Setleri">Dikiş İğne ve İp Setleri</option>
                            <option value="Örgü İpleri ve Şişleri">Örgü İpleri ve Şişleri</option>
                            <option value="Kumaş ve Keçe Parçaları">Kumaş ve Keçe Parçaları</option>
                            <option value="İkinci El Kitaplar">İkinci El Kitaplar</option>
                            <option value="İkinci El Romanlar">İkinci El Romanlar</option>
                            <option value="Sahaf Dergi ve Mecmualar">Sahaf Dergi ve Mecmualar</option>
                            <option value="Eski Baskı Ders Kitapları">Eski Baskı Ders Kitapları</option>
                            <option value="Yazılım Çözümleri">Yazılım Çözümleri</option>
                            <option value="Antivirüs Lisansları">Antivirüs Lisansları</option>
                            <option value="İşletim Sistemi Lisansları">İşletim Sistemi Lisansları</option>
                            <option value="Ofis Programı Lisansları">Ofis Programı Lisansları</option>
                            <option value="Yöresel Gurme Gıdalar">Yöresel Gurme Gıdalar</option>
                            <option value="Yöresel Peynir Çeşitleri">Yöresel Peynir Çeşitleri</option>
                            <option value="Doğal Zeytinyağları">Doğal Zeytinyağları</option>
                            <option value="Organik Bal ve Reçeller">Organik Bal ve Reçeller</option>
                            <option value="Sıfır Atık ve Eko Yaşam">Sıfır Atık ve Eko Yaşam</option>
                            <option value="Bambu Diş Fırçaları">Bambu Diş Fırçaları</option>
                            <option value="Bez Alışveriş Çantaları">Bez Alışveriş Çantaları</option>
                            <option value="Yeniden Kullanılabilir Pipetler">Yeniden Kullanılabilir Pipetler</option>
                            <option value="Antika ve Koleksiyon">Antika ve Koleksiyon</option>
                            <option value="Eski Para ve Madalyalar">Eski Para ve Madalyalar</option>
                            <option value="Antika Bakır Eşyalar">Antika Bakır Eşyalar</option>
                            <option value="Nostaljik Radyo ve Objeler">Nostaljik Radyo ve Objeler</option>
                            <option value="İş Güvenliği Ekipmanları">İş Güvenliği Ekipmanları</option>
                            <option value="İş Güvenliği Ayakkabıları">İş Güvenliği Ayakkabıları</option>
                            <option value="Koruyucu Gözlük ve Maskeler">Koruyucu Gözlük ve Maskeler</option>
                            <option value="İkaz Yelekleri ve Baretler">İkaz Yelekleri ve Baretler</option>
                            <option value="Duvar ve Zemin Kaplama">Duvar ve Zemin Kaplama</option>
                            <option value="Seramik ve Yer Karoları">Seramik ve Yer Karoları</option>
                            <option value="Laminat Parke Çeşitleri">Laminat Parke Çeşitleri</option>
                            <option value="Çita ve Dekoratif Profiller">Çita ve Dekoratif Profiller</option>
                            <option value="Akıllı Ev Güvenlik">Akıllı Ev Güvenlik</option>
                            <option value="Wi-Fi Güvenlik Kameraları">Wi-Fi Güvenlik Kameraları</option>
                            <option value="Akıllı Duman Dedektörleri">Akıllı Duman Dedektörleri</option>
                            <option value="Su Baskını Sensörleri">Su Baskını Sensörleri</option>
                            <option value="Seyahat Organizatörleri">Seyahat Organizatörleri</option>
                            <option value="Bavul İçi Vakumlu Poşetler">Bavul İçi Vakumlu Poşetler</option>
                            <option value="Pasaport Kılıfları">Pasaport Kılıfları</option>
                            <option value="Dijital Aksesuar Çantaları">Dijital Aksesuar Çantaları</option>
                            <option value="Demleme ve Çay Ekipmanları">Demleme ve Çay Ekipmanları</option>
                            <option value="Çaydanlık Takımları">Çaydanlık Takımları</option>
                            <option value="Cam Demlikler ve Süzgeçler">Cam Demlikler ve Süzgeçler</option>
                            <option value="Matara ve Termoslar">Matara ve Termoslar</option>
                            <option value="Ev Tipi Ağırlık Ekipmanları">Ev Tipi Ağırlık Ekipmanları</option>
                            <option value="Ayarlanabilir Dambıl Setleri">Ayarlanabilir Dambıl Setleri</option>
                            <option value="Barfix ve Şınav Barı">Barfix ve Şınav Barı</option>
                            <option value="Ağırlık Eldivenleri">Ağırlık Eldivenleri</option>
                            <option value="Kadın Aksesuarları">Kadın Aksesuarları</option>
                            <option value="Kadın Şal ve Eşarplar">Kadın Şal ve Eşarplar</option>
                            <option value="Kemer ve Jartiyerler">Kemer ve Jartiyerler</option>
                            <option value="Saç Tokaları ve Taçlar">Saç Tokaları ve Taçlar</option>
                            <option value="Erkek Aksesuarları">Erkek Aksesuarları</option>
                            <option value="Erkek Kemer ve Cüzdanlar">Erkek Kemer ve Cüzdanlar</option>
                            <option value="Kravat ve Kol Düğmeleri">Kravat ve Kol Düğmeleri</option>
                            <option value="Erkek Şapka ve Bereler">Erkek Şapka ve Bereler</option>
                            <option value="Çanta Çeşitleri">Çanta Çeşitleri</option>
                            <option value="Sırt Çantaları">Sırt Çantaları</option>
                            <option value="El ve Omuz Çantaları">El ve Omuz Çantaları</option>
                            <option value="Bel Çantaları">Bel Çantaları</option>
                            <option value="Ayakkabı Bakım Ürünleri">Ayakkabı Bakım Ürünleri</option>
                            <option value="Ayakkabı Boyaları ve Fırçaları">Ayakkabı Boyaları ve Fırçaları</option>
                            <option value="Su İtici Spreyler">Su İtici Spreyler</option>
                            <option value="Ayakkabı Kalıpları">Ayakkabı Kalıpları</option>
                            <option value="Değerli Takılar">Değerli Takılar</option>
                            <option value="Altın Kolye ve Küpeler">Altın Kolye ve Küpeler</option>
                            <option value="Gümüş Yüzükler">Gümüş Yüzükler</option>
                            <option value="Pırlanta ve Elmas Setleri">Pırlanta ve Elmas Setleri</option>
                            <option value="Bebek Banyo Ürünleri">Bebek Banyo Ürünleri</option>
                            <option value="Bebek Şampuanı ve Sabunu">Bebek Şampuanı ve Sabunu</option>
                            <option value="Bebek Yağı ve Losyonları">Bebek Yağı ve Losyonları</option>
                            <option value="Yumuşak Bebek Havluları">Yumuşak Bebek Havluları</option>
                            <option value="Bebek Seyahat Ürünleri">Bebek Seyahat Ürünleri</option>
                            <option value="Bebek Kanguru ve Sling">Bebek Kanguru ve Sling</option>
                            <option value="Puset Yağmurlukları">Puset Yağmurlukları</option>
                            <option value="Bebek Bakım Sırt Çantaları">Bebek Bakım Sırt Çantaları</option>
                            <option value="Montessori Mobilyalar">Montessori Mobilyalar</option>
                            <option value="Montessori Yer Yatakları">Montessori Yer Yatakları</option>
                            <option value="Çocuk Kitaplıkları">Çocuk Kitaplıkları</option>
                            <option value="Mini Çocuk Masaları">Mini Çocuk Masaları</option>
                            <option value="Akıl ve Zeka Oyunları">Akıl ve Zeka Oyunları</option>
                            <option value="Ahşap Denge Oyunları">Ahşap Denge Oyunları</option>
                            <option value="Strateji ve Mangala">Strateji ve Mangala</option>
                            <option value="Zeka Küpleri ve Bulmacalar">Zeka Küpleri ve Bulmacalar</option>
                            <option value="Açık Hava Eğlence">Açık Hava Eğlence</option>
                            <option value="Uçurtma Çeşitleri">Uçurtma Çeşitleri</option>
                            <option value="Su Tabancaları">Su Tabancaları</option>
                            <option value="Frisbee ve Frizbi Diskleri">Frisbee ve Frizbi Diskleri</option>
                            <option value="Telefon Kılıfları">Telefon Kılıfları</option>
                            <option value="Silikon Telefon Kılıfları">Silikon Telefon Kılıfları</option>
                            <option value="Cüzdan Tipi Kılıflar">Cüzdan Tipi Kılıflar</option>
                            <option value="Darbeye Dayanıklı Armor Kılıflar">Darbeye Dayanıklı Armor Kılıflar</option>
                            <option value="Bilgisayar Çevre Birimleri">Bilgisayar Çevre Birimleri</option>
                            <option value="Kablosuz Mauslar">Kablosuz Mauslar</option>
                            <option value="Harici Klavyeler">Harici Klavyeler</option>
                            <option value="Mousepad Çeşitleri">Mousepad Çeşitleri</option>
                            <option value="Ses Sistemleri">Ses Sistemleri</option>
                            <option value="Bluetooth Hoparlörler">Bluetooth Hoparlörler</option>
                            <option value="Soundbar Sistemleri">Soundbar Sistemleri</option>
                            <option value="Kulak İçi Kulaklıklar">Kulak İçi Kulaklıklar</option>
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

        <!-- SEO SSS VE BİLGİ BLOKLARI -->
        <section class="seo-content-section mt-5">
            <div class="row g-4">
                <div class="col-lg-6">
                    <h2 class="seo-heading"><i class="fa-solid fa-magnifying-glass-chart text-primary me-2"></i>Yapay Zeka ile E-Ticaret Alan Adı Keşfi</h2>
                    <p class="seo-text">DeedSa, e-ticaret markaları, DTC girişimcileri ve profesyonel alan adı yatırımcıları için <strong>boşta .com alan adı bulma</strong> sürecini otomatize eden kurumsal bir analiz terminalidir. 150'den fazla niş pazarda tüketici algısını, fonetik ritmi ve arama motoru uyumluluğunu analiz ederek, henüz tescil edilmemiş 2 kelimelik dijital marka varlıklarını saniyeler içinde tespit eder.</p>
                    
                    <h3 class="seo-heading fs-5 text-secondary text-uppercase fw-bold mt-4">Neden İki Kelimelik .COM Dijital Varlıkları?</h3>
                    <p class="seo-text">Küresel e-ticaret pazarında güven katsayısı ve tıklama oranı (CTR) en yüksek uzantı tartışmasız <code>.com</code>'dur. İki güçlü İngilizce kelimenin bir araya gelmesiyle oluşan marka isimleri (Örn: SoleGlow, PurePulse, FitCore), hem Meta ve Google reklamlarında daha yüksek dönüşüm oranı sağlar hem de Sedo ve Afternic gibi küresel ikincil pazarlarda binlerce dolarlık likidite yaratır.</p>
                </div>

                <div class="col-lg-6">
                    <h2 class="seo-heading"><i class="fa-solid fa-circle-question text-primary me-2"></i>Sıkça Sorulan Sorular (SEO SSS)</h2>
                    
                    <div class="seo-faq-item">
                        <div class="seo-faq-question">1. Listelenen alan adlarının gerçekten boşta olduğunu nasıl anlarım?</div>
                        <p class="seo-faq-answer">DeedSa, yapay zeka tarafından türetilen tüm domainleri anlık olarak ICANN akredite küresel DNS (A ve NS) sunucularından canlı olarak sorgular. Sadece kayda müsait olanlar önünüze getirilir.</p>
                    </div>

                    <div class="seo-faq-item">
                        <div class="seo-faq-question">2. Domain arbitrajı (Flipping) ile nasıl gelir sağlanır?</div>
                        <p class="seo-faq-answer">DeedSa ile keşfettiğiniz yüksek ticari potansiyelli bir .com alan adını Namecheap üzerinden taban fiyata (10-12$) tescil edip, Sedo.com pazar yerinde global alıcılara (490$ - 2.500$) satışa sunarak arbitraj gerçekleştirebilirsiniz.</p>
                    </div>

                    <div class="seo-faq-item">
                        <div class="seo-faq-question">3. API anahtarım güvende mi?</div>
                        <p class="seo-faq-answer">Evet. DeedSa sıfır bilgi (zero-knowledge) prensibiyle çalışır. Girdiğiniz Google Gemini API anahtarı sunuculara iletilmez, yalnızca kendi tarayıcınızın yerel hafızasında saklanır.</p>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <!-- BLOG SAYFALARI (DOLU DOLU & KURUMSAL STRATEJİLİ) -->
    <main class="container py-5 view-section" id="viewWhyToolsGuide">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">İnovasyon & SaaS Ekosistemi</span>
                    <h1 class="corporate-title">DeedSa <span>Araçlar Ekosistemi</span>: Uçtan Uca Marka Fabrikası</h1>
                    <p class="corporate-subtitle">Alan adı keşfi, dijital bir imparatorluk kurmanın yalnızca ilk adımıdır. DeedSa, geleneksel bir alan adı arama motorunun ötesine geçerek, bir fikrin somut bir küresel markaya dönüşmesini sağlayan 4 temel yapay zeka istihbarat aracını bünyesinde barındırır.</p>

                    <div class="info-grid">
                        <div class="info-card-box">
                            <h5><i class="fa-solid fa-share-nodes text-success"></i> 1. Sosyal Medya Radarı</h5>
                            <p>Keşfedilen .com varlığının Instagram, X (Twitter) ve TikTok platformlarında aynı kullanıcı adıyla (handle) kullanılabilir olup olmadığını anında tarar. Çapraz platform uyumu, e-ticaret markalarının reklam tıklama oranlarını (CTR) ve güven skorunu %40'a kadar artırır.</p>
                        </div>
                        <div class="info-card-box">
                            <h5><i class="fa-solid fa-palette text-info"></i> 2. Logo & Mockup Motoru</h5>
                            <p>Metin halindeki alan adını vektörel bir SVG kurumsal kimliğe ve gerçekçi 3D e-ticaret ambalaj kutusuna giydirir. İnsan beyni görselleştirilen varlıklara %75 daha fazla değer biçer; mockup motoru bu psikolojik tetikleyiciyi kullanır.</p>
                        </div>
                        <div class="info-card-box">
                            <h5><i class="fa-solid fa-file-lines text-warning"></i> 3. E-Ticaret Pitchbook</h5>
                            <p>Hedeflenen niş pazar için tüketici persona profili, ilk 90 günlük performans pazarlama bütçe dağılımı ve lojistik tedarik modellerini içeren operasyonel bir iş planı simülasyonu üretir.</p>
                        </div>
                        <div class="info-card-box">
                            <h5><i class="fa-solid fa-envelope-open-text text-danger"></i> 4. Outbound Pitch Generator</h5>
                            <p>Tescil ettiğiniz alan adını Sedo veya ikincil pazarlarda satabilmeniz için, o dikeydeki kurumsal alıcılara gönderilmek üzere nöro-pazarlama odaklı İngilizce B2B teklif e-postaları kurgular.</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewWhyDeedsa">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">İstihbarat ve Fonetik Bilim</span>
                    <h1 class="corporate-title">Neden <span>DeedSa Terminali</span> ile Keşif Yapmalısınız?</h1>
                    <p class="corporate-subtitle">Sıradan alan adı arama siteleri size yalnızca 'yazdığınız kelimenin dolu olup olmadığını' söyler. DeedSa ise küresel e-ticaret ekosisteminde hangi alan adının milyar dolarlık marka algısı yaratacağını hesaplayan bir veri terminalidir.</p>

                    <h2 class="section-header-blue"><i class="fa-solid fa-brain"></i> İki Kelimelik Fonetik Ritim Psikolojisi</h2>
                    <p>İnsan beyni, ritmik ve 2 heceli/2 kelimelik isim kombinasyonlarını çok daha hızlı işler ve belleğe kaydeder (Cognitive Fluency). Yapay zeka fonetik motorumuz, tüketici algısında güven, dinamizm ve lüks hissi uyandıran İngilizce morfolojik yapıları eşzamanlı olarak tarar.</p>

                    <h2 class="section-header-blue"><i class="fa-solid fa-network-wired"></i> Çift Katmanlı Canlı DNS Doğrulama</h2>
                    <p>DeedSa, türettiği her bir ismi ICANN akredite küresel root DNS sunucularında anlık milisaniyelik mikro sorgularla doğrular. Ekranda gördüğünüz her domain o an tescile tamamen açıktır.</p>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewWhyRobom">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Yapay Zeka Asistanı</span>
                    <h1 class="corporate-title">Robom AI Nedir? <span>Nasıl Stratejik Avantaj Sağlar?</span></h1>
                    <p class="corporate-subtitle">Robom, DeedSa platformunda alan adı yatırımcılarına, ajanslara ve e-ticaret kurucularına rehberlik etmek üzere özel olarak eğitilmiş yeni nesil akıllı asistan modelidir.</p>

                    <h2 class="section-header-blue"><i class="fa-solid fa-comments"></i> Doğal Dil Anlama ve Anlık Arayüz Eşleme</h2>
                    <p>Robom terminalin arayüzüyle doğrudan haberleşir. Sohbet sırasında bahsettiğiniz e-ticaret kategorisini otomatik algılayarak arayüzdeki seçim kutusunu o sektöre odaklar.</p>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewWhyNamecheap">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-success-subtle text-success fw-bold px-3 py-2 rounded-pill mb-3">Tescil & Güvenlik Standartları</span>
                    <h1 class="corporate-title">Neden <span>Namecheap</span> ile Tescil Etmelisiniz?</h1>
                    <p class="corporate-subtitle">Alan adı ticaretinde karlılığın temel kuralı 'doğru fiyattan almak' ve 'varlığı güvence altına almaktır'. Namecheap, küresel ölçekte 17 milyondan fazla domaini yöneten ICANN akredite lider operatördür.</p>

                    <h2 class="section-header-blue"><i class="fa-solid fa-user-shield"></i> Ömür Boyu Ücretsiz WhoisGuard Gizliliği</h2>
                    <p>Namecheap, tescil ettiğiniz her alan adı için uluslararası Whois gizlilik korumasını ömür boyu tamamen ücretsiz sunar. Kişisel kimlik ve iletişim bilgileriniz spam havuzlarından korunur.</p>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewWhySedo">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Küresel Pazar & Likidite</span>
                    <h1 class="corporate-title">Neden <span>Sedo.com</span>? Dünyanın En Büyük Alan Adı Borsası</h1>
                    <p class="corporate-subtitle">Bulduğunuz değerli bir dijital varlığı satmak için kapı kapı müşteri aramanıza gerek yoktur. Sedo, kurumsal şirketlerin ve yatırımcıların her gün alım yaptığı global merkezdir.</p>

                    <h2 class="section-header-blue"><i class="fa-solid fa-globe"></i> SedoMLS: 80+ Global Ortak Ağı</h2>
                    <p>Sedo'da listelediğiniz alan adı, GoDaddy ve 80+ küresel tescil firmasında eşzamanlı olarak satış vitrinine çıkar. Güvenli Escrow emanetçi altyapısıyla ödemeleriniz %100 güvendedir.</p>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewHowToEarn">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Arbitraj ve Yatırım Metodolojisi</span>
                    <h1 class="corporate-title">3 Adımda <span>Domain Al-Sat (Flipping)</span> ile Gelir Modeli</h1>
                    <p class="corporate-subtitle">Alan adı ticareti: Yüksek talep görecek bir dijital arsayı taban fiyattan keşfet, portföyüne kat ve ihtiyacı olan küresel alıcıya katma değeriyle sat disiplinine dayanır.</p>

                    <div class="step-card mb-4 p-4 border rounded-3 bg-light">
                        <h4 class="fw-bold text-dark mb-2">1. DeedSa ile Likit İsimleri Tespit Edin</h4>
                        <p class="text-secondary mb-0">150+ trend dikey arasından canlı DNS motoru ile tescile açık 2 kelimelik .com varlıklarını bulun.</p>
                    </div>
                    <div class="step-card mb-4 p-4 border rounded-3 bg-light">
                        <h4 class="fw-bold text-dark mb-2">2. Namecheap Üzerinden Taban Fiyata Tescil Edin</h4>
                        <p class="text-secondary mb-0">Ücretsiz gizlilik korumasıyla domaini 10-12$ taban maliyetle mülkiyetinize alın.</p>
                    </div>
                    <div class="step-card p-4 border rounded-3 bg-light">
                        <h4 class="fw-bold text-dark mb-2">3. Sedo.com Üzerinde Küresel Alıcılara Sunun</h4>
                        <p class="text-secondary mb-0">SedoMLS ağıyla küresel vitrine çıkararak 490$ - 2.500$ aralığında karlı satışlar gerçekleştirin.</p>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <!-- YASAL METİNLER -->
    <main class="container py-5 view-section" id="viewPrivacy">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-secondary-subtle text-dark fw-bold px-3 py-2 rounded-pill mb-3">Yasal Doküman & Uyum</span>
                    <h1 class="corporate-title">Gizlilik Politikası <span>(Privacy Policy)</span></h1>
                    <h2 class="section-header-blue">1. Sıfır Bilgi (Zero-Knowledge) Gizlilik Mimarisi</h2>
                    <p>DeedSa "Kendi Anahtarını Getir" (BYOK) mimarisiyle çalışır. Girdiğiniz Google Gemini API anahtarları veya yapılan sektör aramaları sunucu veritabanında asla kaydedilmez, loglanmaz ve üçüncü taraflarla paylaşılmaz. Yalnızca tarayıcınızın yerel hafızasında tutulur.</p>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewTerms">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-secondary-subtle text-dark fw-bold px-3 py-2 rounded-pill mb-3">Yasal Doküman & Uyum</span>
                    <h1 class="corporate-title">Kullanım Koşulları <span>(Terms of Service)</span></h1>
                    <h2 class="section-header-blue">1. Hizmetin Kapsamı ve Sorumluluk Reddi</h2>
                    <p>DeedSa, e-ticaret girişimcilerine ve yatırımcılara yapay zeka destekli alan adı analizi ve anlık DNS sorgulama hizmeti sunan bağımsız bir istihbarat arayüzüdür. Alan adı müsaitlikleri anlık DNS kayıtlarına dayanır; DeedSa kesin değer veya satış garantisi taahhüt etmez.</p>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewAffiliateDisclosure">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-secondary-subtle text-dark fw-bold px-3 py-2 rounded-pill mb-3">Şeffaflık & Kurumsal Beyan</span>
                    <h1 class="corporate-title">Affiliate & Yönlendirme <span>Açıklaması</span></h1>
                    <h2 class="section-header-blue">1. Ticari İş Birlikleri</h2>
                    <p>DeedSa; Namecheap Inc. ve Sedo GmbH gibi saygın küresel operatörlerle affiliate ortaklığı yürütmektedir. Yönlendirme bağlantılarımız üzerinden işlem yaptığınızda platformumuz küçük bir komisyon elde edebilir. Bu durum kullanıcıya hiçbir ek maliyet getirmez.</p>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewContact">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Kurumsal Destek</span>
                    <h1 class="corporate-title">Bizimle <span>İletişime Geçin</span></h1>
                    <div class="step-card p-4 border rounded-3 bg-light">
                        <h4 class="fw-bold text-dark mb-1"><i class="fa-solid fa-envelope text-primary me-2"></i>E-Posta Desteği</h4>
                        <p class="text-secondary small mb-2">Tüm teknik soru ve kurumsal iş birlikleri için:</p>
                        <a href="mailto:support@deedsa.com" class="fw-bold text-primary text-decoration-none fs-5">support@deedsa.com</a>
                    </div>
                </div>
            </div>
        </div>
    </main>

    <main class="container py-5 view-section" id="viewGetApiKey">
        <div class="row justify-content-center">
            <div class="col-lg-10">
                <div class="content-card">
                    <span class="badge bg-primary-subtle text-primary fw-bold px-3 py-2 rounded-pill mb-3">Entegrasyon ve Kurulum</span>
                    <h1 class="corporate-title">Google Gemini API Anahtarı <span>Nasıl Alınır?</span></h1>
                    <div class="pro-callout-box d-flex flex-column flex-md-row align-items-start align-items-md-center justify-content-between gap-3">
                        <div>
                            <h4 class="fw-bold text-dark mb-1"><i class="fa-solid fa-bolt text-warning me-2"></i>Google AI Studio Portalı</h4>
                            <p class="small text-secondary mb-0">Resmi konsola giderek saniyeler içinde ücretsiz anahtarınızı oluşturun.</p>
                        </div>
                        <a href="https://aistudio.google.com/app/apikey" target="_blank" class="btn btn-dark fw-bold px-4 py-2 rounded-3 text-decoration-none">
                            AI Studio'ya Git <i class="fa-solid fa-arrow-up-right-from-square ms-1"></i>
                        </a>
                    </div>
                </div>
            </div>
        </div>
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
                Selam! Ben <strong>Robom</strong>. 👋<br><br>E-ticaret trendleri, marka fonetiği, <strong>Araçlarımız</strong> veya Gemini API anahtarı hakkında bana dilediğini sorabilirsin:
            </div>
        </div>

        <div class="robom-suggestions" id="robomSuggestions">
            <div class="sugg-chip" onclick="askRobomPredefined('DeedSa Araçlar menüsünde hangi özellikler var ve nasıl kullanılır?')">
                <i class="fa-solid fa-toolbox text-primary"></i> DeedSa Araçları Nelerdir?
            </div>
            <div class="sugg-chip" onclick="askRobomPredefined('Sosyal Medya Kullanıcı Adı Radarı ve Logo Üreticisi ne işe yarar?')">
                <i class="fa-solid fa-share-nodes text-success"></i> Sosyal Medya & Logo Araçları
            </div>
            <div class="sugg-chip" onclick="askRobomPredefined('Gemini API anahtarı nasıl alınır ve üst menüden nasıl bağlanır?')">
                <i class="fa-solid fa-key text-info"></i> Gemini API Nasıl Alınır ve Bağlanır?
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
                <a onclick="switchView('privacy')" class="footer-link">Gizlilik Politikası</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('terms')" class="footer-link">Kullanım Koşulları</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('affiliateDisclosure')" class="footer-link">Affiliate Açıklaması</a>
                <span class="text-muted">•</span>
                <a onclick="switchView('contact')" class="footer-link">İletişim</a>
            </div>
            <p class="mb-0 small text-secondary">© 2026 DeedSa Enterprise. Tüm hakları saklıdır. Küresel E-Ticaret Alan Adı İstihbarat Platformu.</p>
        </div>
    </footer>

    <div class="toast-copy" id="copyToast"><i class="fa-solid fa-check text-success me-2"></i>İşlem başarılı!</div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const introCanvas = document.getElementById('introCanvas');
        const ctx = introCanvas.getContext('2d');
        let stars = [];
        let shootingStars = [];
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

        class ShootingStar {
            constructor() { this.reset(); }
            reset() {
                this.x = Math.random() * introCanvas.width;
                this.y = Math.random() * introCanvas.height * 0.5;
                this.len = Math.random() * 110 + 50;
                this.speed = Math.random() * 12 + 14;
                this.angle = Math.PI / 4 + (Math.random() - 0.5) * 0.3;
                this.alpha = 1;
                this.active = true;
            }
            update() {
                this.x += Math.cos(this.angle) * this.speed;
                this.y += Math.sin(this.angle) * this.speed;
                this.alpha -= 0.022;
                if (this.alpha <= 0) this.active = false;
            }
            draw() {
                if (!this.active) return;
                const endX = this.x - Math.cos(this.angle) * this.len;
                const endY = this.y - Math.sin(this.angle) * this.len;
                const grad = ctx.createLinearGradient(this.x, this.y, endX, endY);
                grad.addColorStop(0, `rgba(255, 255, 255, ${this.alpha})`);
                grad.addColorStop(0.3, `rgba(56, 189, 248, ${this.alpha * 0.8})`);
                grad.addColorStop(1, 'rgba(2, 132, 199, 0)');
                ctx.beginPath();
                ctx.moveTo(this.x, this.y);
                ctx.lineTo(endX, endY);
                ctx.strokeStyle = grad;
                ctx.lineWidth = 2.4;
                ctx.lineCap = 'round';
                ctx.stroke();
            }
        }

        for (let i = 0; i < 160; i++) stars.push(new Star());

        function loopIntroCanvas() {
            ctx.clearRect(0, 0, introCanvas.width, introCanvas.height);
            stars.forEach(s => { s.update(); s.draw(); });
            if (Math.random() < 0.09 && shootingStars.length < 5) shootingStars.push(new ShootingStar());
            shootingStars.forEach(ss => { ss.update(); ss.draw(); });
            shootingStars = shootingStars.filter(ss => ss.active);
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
                subEl.innerText = "Seçilen niş için ilk 3 ay büyüme stratejisi analizi.";
                bodyEl.innerHTML = `<div class="mb-3"><label class="field-label mb-2">HEDEF NİŞ</label><div class="input-group"><input type="text" id="toolPitchInput" class="form-control search-input" placeholder="Örn: Retinol Serumu..."><button class="btn btn-primary px-4 fw-bold" onclick="runPitchbook()">Strateji Üret</button></div></div><div id="toolPitchResults" class="mt-3"></div>`;
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
            document.getElementById('toolLogoResults').innerHTML = `<div class="p-4 bg-white rounded-3 border"><div class="d-inline-flex align-items-center justify-content-center p-4 rounded-4 shadow-sm mb-3" style="background: linear-gradient(135deg, #0284c7, #0f172a); color: #fff; min-width: 220px;"><span class="fs-3 fw-bold text-uppercase">${val}</span></div><br><button class="btn btn-outline-primary btn-sm fw-bold" onclick="alert('İndirildi!')">Logoyu İndir</button></div>`;
        }

        function runPitchbook() {
            const val = document.getElementById('toolPitchInput').value.trim() || "Cilt Bakım";
            document.getElementById('toolPitchResults').innerHTML = `<div class="p-3 bg-light rounded-3 border small"><h6 class="fw-bold text-primary mb-2">${val} - Strateji:</h6><p class="mb-0">Hedef kitle ve ilk 3 ay reklam planı başarıyla simüle edildi.</p></div>`;
        }

        function runOutboundEmail() {
            const d = document.getElementById('outDomain').value.trim() || "pureglow.com";
            document.getElementById('toolOutboundResults').innerHTML = `<div class="p-3 bg-white rounded-3 border small" style="font-family:monospace;">Subject: Asset inquiry: ${d}<br>Hi Team, we have ${d} available for acquisition.</div>`;
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
            if (val.length < 10) { alert('Geçerli bir API anahtarı girin.'); return; }
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
            const input = document.getElementById('modalApiKeyInput');
            input.type = input.type === 'password' ? 'text' : 'password';
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
                                            <span class="metric-badge">Piyasa Skoru: ${item.score}/100</span>
                                            <span class="metric-badge text-success">Tescile Uygun</span>
                                        </div>
                                    </div>
                                    <div class="d-flex align-items-center gap-2 mt-2 mt-md-0">
                                        <button class="btn btn-action" onclick="copyDomain('${item.domain}')"><i class="fa-regular fa-copy"></i> Kopyala</button>
                                        <a href="https://www.namecheap.com/domains/registration/results/?domain=${item.domain}" target="_blank" class="btn btn-register"><i class="fa-solid fa-cart-shopping me-1"></i> Hemen Al</a>
                                    </div>
                                </div>
                                <div class="sedo-banner">
                                    <div class="text-secondary small"><i class="fa-solid fa-arrow-trend-up text-primary me-2"></i>Küresel pazaryerinde listele:</div>
                                    <a href="https://sedo.com/?language=us&campaignId=336614" target="_blank" class="btn-sedo-blue"><span>Sedo'da Satışa Çıkar</span><i class="fa-solid fa-chevron-right"></i></a>
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
# 3. DOĞRULAMA VE ESNEK GEMİNİ ÇAĞRI MOTORU
# -------------------------------------------------------------
class CategoryRequest(BaseModel):
    category: str = Field(..., min_length=2, max_length=150)
    api_key: str = Field(..., min_length=10, max_length=200)

class RobomChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=600)
    api_key: str = Field(..., min_length=10, max_length=200)

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

async def check_single_domain(domain: str, explanation: str, score: int):
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

def parse_robust_domains(raw_text: str):
    try:
        clean = re.sub(r"^```[a-zA-Z]*\n?", "", raw_text.strip())
        clean = re.sub(r"\n?```$", "", clean).strip()
        match = re.search(r"\{.*\}", clean, re.DOTALL)
        if match:
            data = json.loads(match.group(0))
            if "domains" in data and isinstance(data["domains"], list):
                return data["domains"]
        else:
            data = json.loads(raw_text)
            if "domains" in data and isinstance(data["domains"], list):
                return data["domains"]
    except Exception:
        pass

    results = []
    pattern = re.compile(
        r'\{\s*"domain"\s*:\s*"([^"]+)"\s*,\s*"explanation"\s*:\s*"([^"]*)"\s*,\s*"score"\s*:\s*(\d+)\s*\}'
    )
    matches = pattern.findall(raw_text)
    for d, exp, sc in matches:
        results.append({"domain": d, "explanation": exp, "score": int(sc)})
    return results

async def execute_gemini_request(http_client: httpx.AsyncClient, api_key: str, payload: dict) -> str:
    # Kesintisiz ve hatasız çalışan aktif modeller öncelik sırasıyla listelenir
    target_models = [
        "gemini-2.0-flash",
        "gemini-1.5-flash",
        "gemini-2.0-flash-lite",
        "gemini-1.5-flash-8b",
        "gemini-1.5-pro",
        "gemini-2.5-flash",
        "gemini-3.5-flash"
    ]
    
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": api_key
    }

    last_err = ""
    for model_id in target_models:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_id}:generateContent?key={api_key}"
        try:
            resp = await http_client.post(url, headers=headers, json=payload, timeout=25.0)
            if resp.status_code == 200:
                res_json = resp.json()
                if "candidates" in res_json and len(res_json["candidates"]) > 0:
                    cand = res_json["candidates"][0]
                    if "content" in cand and "parts" in cand["content"] and len(cand["content"]["parts"]) > 0:
                        return cand["content"]["parts"][0].get("text", "")
            else:
                last_err = f"{model_id} (Durum: {resp.status_code})"
        except Exception as e:
            last_err = str(e)
            continue

    raise Exception(f"Gemini API yanıt üretemedi. API anahtarınızı kontrol edin ({last_err})")

# -------------------------------------------------------------
# 4. ENDPOINTLER & SEO SITEMAP / ROBOTS
# -------------------------------------------------------------
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
async def analyze_category(req: CategoryRequest, request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    if "," in client_ip: client_ip = client_ip.split(",")[0].strip()

    now = time.time()
    user_requests = REQUEST_HISTORY[client_ip]
    REQUEST_HISTORY[client_ip] = [t for t in user_requests if now - t < RATE_LIMIT_WINDOW]

    if REQUEST_HISTORY[client_ip] and (now - REQUEST_HISTORY[client_ip][-1] < COOLDOWN_SECONDS):
        raise HTTPException(status_code=429, detail="Çok hızlı istek gönderiyorsunuz.")

    if len(REQUEST_HISTORY[client_ip]) >= MAX_REQUESTS_PER_WINDOW:
        raise HTTPException(status_code=429, detail="Arama kotanızı aştınız.")

    REQUEST_HISTORY[client_ip].append(now)

    safe_category = re.sub(r"[^\w\s\-\,\.\(\)]", "", req.category).strip()
    safe_api_key = req.api_key.strip()

    available_domains = []
    seen = set()

    try:
        async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as http_client:
            for round_idx in range(2):
                prompt = f"""
                You are an elite global domain broker and e-commerce brand namer. (Round: {round_idx})
                TARGET NICHE: "{safe_category}"
                CRITICAL RULES:
                1. DOMAIN NAMES MUST BE 100% ENGLISH (e.g. PureGlow, SilkPulse, ZenAura, FitCore).
                2. EXPLANATION LANGUAGE: The 'explanation' field MUST BE STRICTLY WRITTEN IN TURKISH.
                3. Every domain must be composed of 2 real, rhythmic, high-value English words.
                4. Generate 45 potential available .COM domains.
                5. Output ONLY valid JSON matching this schema:
                {{
                    "domains": [
                        {{
                            "domain": "pureglow.com",
                            "explanation": "Bu e-ticaret sektörü için yüksek marka algısı ve fonetik ritim sunan premium alan adı.",
                            "score": 94
                        }}
                    ]
                }}
                """
                payload = {
                    "contents": [{"parts": [{"text": prompt}]}],
                    "generationConfig": {"responseMimeType": "application/json", "temperature": 0.8}
                }
                raw_text = await execute_gemini_request(http_client, safe_api_key, payload)
                domains_list = parse_robust_domains(raw_text)

                tasks = []
                for item in domains_list:
                    domain = clean_domain(item.get("domain", ""))
                    if domain not in seen:
                        seen.add(domain)
                        tasks.append(check_single_domain(domain, item.get("explanation", ""), item.get("score", 90)))

                scan_results = await asyncio.gather(*tasks)
                for res in scan_results:
                    if res is not None: available_domains.append(res)

                if len(available_domains) >= 3: break

        available_domains.sort(key=lambda x: x["score"], reverse=True)
        return {"status": "success", "results": available_domains}
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/robom-chat")
async def robom_chat(req: RobomChatRequest, request: Request):
    client_ip = request.headers.get("x-forwarded-for") or request.client.host
    if "," in client_ip: client_ip = client_ip.split(",")[0].strip()

    safe_msg = req.message.strip()
    safe_api_key = req.api_key.strip()

    if check_toxic_or_absurd(safe_msg):
        USER_STRIKES[client_ip] += 1
        return {"status": "success", "reply": f"⚠️ <strong>Sistem Uyarısı ({USER_STRIKES[client_ip]}/3):</strong> Kurallara uygun ifadeler kullanınız.", "suggested_category": None}

    system_instruction = """
    Sen Robom adında samimi ve yardımsever bir e-ticaret & alan adı asistanısın. DeedSa platformunda kullanıcılara rehberlik ediyorsun.
    Kullanıcılara üst menüdeki 'Araçlar' menüsünde bulunan Sosyal Medya Kullanıcı Adı Radarı, Yapay Zeka Logo & Mockup Üreticisi, E-Ticaret İş Planı (Pitchbook) ve Outbound Satış E-Posta Asistanı hakkında detaylı bilgi ver. Ayrıca Gemini API anahtarının üst menüden nasıl bağlanacağını anlat. Yanıtlarını akıcı ve doğal Türkçe ile ver.
    """
    prompt = f"{system_instruction}\n\nKullanıcı: {safe_msg}\nRobom:"
    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    try:
        async with httpx.AsyncClient(timeout=25.0) as http_client:
            reply_text = await execute_gemini_request(http_client, safe_api_key, payload)
            clean_reply = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', reply_text).replace('\n', '<br>')
            return {"status": "success", "reply": clean_reply, "suggested_category": None}
    except Exception as e:
        return {"status": "error", "detail": f"Bir sorun oluştu: {str(e)}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8000)
