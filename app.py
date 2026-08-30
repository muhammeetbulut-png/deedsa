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
# 2. ARAYÜZ VE HTML İÇERİĞİ (TÜM MEVCUT + YENİ EKSİKSİZ KATEGORİLER VE MOBİL MENÜ)
# -------------------------------------------------------------
HTML_CONTENT = """
<!DOCTYPE html>
<html lang="tr" prefix="og: https://ogp.me/ns#">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    
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
        .robom-input:focus { 
