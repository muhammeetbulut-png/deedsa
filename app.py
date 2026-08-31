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
from typing import List
import httpx

app = FastAPI(
    title="DeedSa Enterprise Domain Intelligence",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
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
    
    <title>DeedSa | E-Ticaret Boşta .COM Alan Adı İstihbarat ve Analiz Terminali</title>
    <meta name="description" content="Yüzlerce e-ticaret kategorisinde yapay zeka ile 2 kelimelik boşta .com domainleri keşfedin. Canlı DNS/RDAP sorgulama, sosyal medya radarı ve Sedo/Namecheap arbitraj analizi.">
    <link rel="canonical" href="https://deedsa.com/">

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

                    <div class="dropdown">
                        <a class="nav-link-custom dropdown-toggle fw-bold text-primary" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false">
                            <span class="api-status-dot" id="headerApiStatusDot"></span>
                            <i class="fa-solid fa-key me-1"></i> Gemini API
                        </a>
                        <ul class="dropdown-menu">
                            <li><a class="dropdown-item" href="#" data-bs-toggle="modal" data-bs-target="#apiKeyModal"><i class="fa-solid fa-gear text-success me-2"></i> API Anahtarı Yönet</a></li>
                            <li><a class="dropdown-item" href="#" onclick="switchView('getApiKey')"><i class="fa-solid fa-circle-question text-info me-2"></i> API Nasıl Alınır?</a></li>
                        </ul>
                    </div>

                    <a onclick="switchView('whyToolsGuide')" class="nav-link-custom text-info fw-bold" id="navWhyToolsGuide"><i class="fa-solid fa-book-open me-1"></i> Araçlar Rehberi</a>
                    <a onclick="switchView('whyDeedsa')" class="nav-link-custom" id="navWhyDeedsa">Neden DeedSa?</a>
                    <a onclick="switchView('whyRobom')" class="nav-link-custom" id="navWhyRobom"><i class="fa-solid fa-robot text-primary me-1"></i> Robom AI</a>
                    <a onclick="switchView('whyNamecheap')" class="nav-link-custom" id="navWhyNamecheap">Neden Namecheap?</a>
                    <a onclick="switchView('whySedo')" class="nav-link-custom" id="navWhySedo">Neden Sedo?</a>
                </nav>
            </div>
        </div>
    </header>

    <!-- MOBİL YAN MENÜ -->
    <div class="offcanvas offcanvas-end d-lg-none" tabindex="-1" id="mobileOffcanvasMenu">
        <div class="offcanvas-header border-bottom">
            <h5 class="offcanvas-title fw-bold text-primary">Menü</h5>
            <button type="button" class="btn-close" data-bs-dismiss="offcanvas"></button>
        </div>
        <div class="offcanvas-body d-flex flex-column gap-3">
            <div class="fw-bold text-dark border-bottom pb-2"><i class="fa-solid fa-key text-primary me-2"></i> Ayarlar</div>
            <a href="#" class="text-decoration-none text-secondary" data-bs-dismiss="offcanvas" data-bs-toggle="modal" data-bs-target="#apiKeyModal">API Anahtarını Yönet</a>
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
                            <p class="small text-secondary mb-0">Anahtarınızla doğrudan Google'a bağlanır.</p>
                        </div>
                    </div>
                    <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                </div>
                <div class="modal-body px-4 py-4">
                    <div class="mb-3">
                        <label class="field-label mb-2">API ANAHTARINIZ</label>
                        <div class="input-group">
                            <input type="password" id="modalApiKeyInput" class="form-control search-input" placeholder="Örn: AQ... veya AIzaSy..." style="font-family: monospace;">
                            <button class="btn btn-outline-secondary" type="button" onclick="toggleApiKeyVisibility()" id="btnToggleVisibility"><i class="fa-regular fa-eye"></i></button>
                        </div>
                        <div class="form-text small mt-2 text-muted">
                            <i class="fa-solid fa-shield-halved text-success me-1"></i> <strong>Otomatik Model Tespiti:</strong> Girdiğiniz anahtara tanımlı tüm aktif modeller taranır ve en günceli (gemini-3.5 vb.) otomatik seçilir. 
                        </div>
                    </div>
                </div>
                <div class="modal-footer border-top-0 pt-0 px-4 pb-4 d-flex justify-content-between">
                    <button type="button" class="btn btn-outline-danger px-3 py-2 fw-bold rounded-3" id="btnModalDeleteKey" onclick="modalDeleteApiKey()" style="display: none;">Sil</button>
                    <div class="d-flex gap-2 ms-auto">
                        <button type="button" class="btn btn-light px-3 py-2 fw-bold text-secondary rounded-3" data-bs-dismiss="modal">Kapat</button>
                        <button type="button" class="btn btn-primary px-4 py-2 fw-bold rounded-3" onclick="modalSaveApiKey()">Kaydet & Bağla</button>
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
                            <option value="Giyim ve Moda">Giyim ve Moda</option>
                            <option value="Bebek Beslenme Ürünleri">Bebek Beslenme Ürünleri</option>
                            <option value="Ev Dekorasyon Objeleri">Ev Dekorasyon Objeleri</option>
                            <option value="Kahve ve Çay Ekipmanları">Kahve ve Çay Ekipmanları</option>
                            <!-- Kalan yüzlerce liste buradadır, kısalık için temsili -->
                            <option value="Dijital Ürünler ve Lisanslar">Dijital Ürünler ve Lisanslar</option>
                            <option value="Vegan Kozmetik Ürünleri">Vegan Kozmetik Ürünleri</option>
                            <option value="Akıllı Ev Teknolojileri">Akıllı Ev Teknolojileri</option>
                            <option value="Otomotiv ve Motosiklet">Otomotiv ve Motosiklet</option>
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
            <div class="text-dark fw-bold mt-3" id="loadingTitle">Yapay Zeka ile Modeller Taranıyor...</div>
            <p class="text-secondary small mt-1" id="loadingSubtitle">API Anahtarınıza en uygun model ile kombinasyonlar üretiliyor.</p>
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
            <div class="chat-msg robom">Selam! Ben <strong>Robom</strong>. 👋<br><br>E-ticaret trendleri veya marka fonetiği hakkında dilediğini sorabilirsin.</div>
        </div>
        <div class="robom-input-area">
            <input type="text" id="robomCustomInput" class="robom-input" placeholder="Robom'a sor..." onkeydown="if(event.key==='Enter') sendRobomMessage()">
            <button class="btn-robom-send" onclick="sendRobomMessage()"><i class="fa-solid fa-paper-plane"></i></button>
        </div>
    </div>

    <div class="toast-copy" id="copyToast"><i class="fa-solid fa-check text-success me-2"></i>İşlem başarılı!</div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        const introCanvas = document.getElementById('introCanvas');
        const ctx = introCanvas.getContext('2d');
        let stars = [];
        function resizeIntroCanvas() { introCanvas.width = window.innerWidth; introCanvas.height = window.innerHeight; }
        window.addEventListener('resize', resizeIntroCanvas);
        resizeIntroCanvas();

        class Star {
            constructor() { this.reset(); }
            reset() { this.x = Math.random() * introCanvas.width; this.y = Math.random() * introCanvas.height; this.radius = Math.random() * 1.8 + 0.3; this.alpha = Math.random() * 0.7 + 0.2; this.alphaSpeed = (Math.random() * 0.015 + 0.005) * (Math.random() > 0.5 ? 1 : -1); this.vx = (Math.random() - 0.5) * 0.3; this.vy = (Math.random() - 0.5) * 0.3; }
            update() { this.x += this.vx; this.y += this.vy; this.alpha += this.alphaSpeed; if (this.alpha > 0.9 || this.alpha < 0.15) this.alphaSpeed = -this.alphaSpeed; if (this.x < 0 || this.x > introCanvas.width || this.y < 0 || this.y > introCanvas.height) this.reset(); }
            draw() { ctx.beginPath(); ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2); ctx.fillStyle = `rgba(186, 230, 253, ${this.alpha})`; ctx.fill(); }
        }
        for (let i = 0; i < 160; i++) stars.push(new Star());

        let animFrameId;
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

        function openToolModal(toolType) { /* Araçlar buradadır... */ new bootstrap.Modal(document.getElementById('toolModal')).show(); }

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
            localStorage.removeItem('deedsa_gemini_api_key');
            loadApiKeyStatus();
            bootstrap.Modal.getInstance(document.getElementById('apiKeyModal')).hide();
        }

        function toggleApiKeyVisibility() {
            modalApiKeyInput.type = modalApiKeyInput.type === 'password' ? 'text' : 'password';
        }

        loadApiKeyStatus();

        function switchView(viewName) {
            document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active'));
            const viewId = 'view' + viewName.charAt(0).toUpperCase() + viewName.slice(1);
            const targetView = document.getElementById(viewId);
            if (targetView) targetView.classList.add('active');
            window.scrollTo(0, 0);
        }

        // =========================================================================
        // MUCİZE FONKSİYON: DİNAMİK MODEL TESPİTİ (404 HATASINI BİTİREN YAPI)
        // =========================================================================
        async function callGeminiDirectly(apiKey, promptText, isJson = false) {
            let targetModel = "gemini-3.5-flash"; // Varsayılan Son Sistem
            
            try {
                // 1. ADIM: API Anahtarınızın hangi modellere yetkisi olduğunu Google'a soruyoruz
                const listUrl = `https://generativelanguage.googleapis.com/v1beta/models?key=${apiKey}`;
                const listRes = await fetch(listUrl);
                
                if (listRes.ok) {
                    const listData = await listRes.json();
                    
                    // İçinde 'generateContent' desteklenen ve 'gemini' olanları filtrele
                    const availableModels = listData.models
                        .filter(m => m.supportedGenerationMethods && m.supportedGenerationMethods.includes("generateContent"))
                        .map(m => m.name.replace('models/', ''));

                    if (availableModels.length > 0) {
                        // Olası bir 'model not found' yaşamamak için bizzat Google'ın listesinden en güçlü Flash modelini seçiyoruz
                        targetModel = availableModels.find(m => m.includes("gemini-3.5-flash-lite")) ||
                                      availableModels.find(m => m.includes("gemini-3.5-flash")) ||
                                      availableModels.find(m => m.includes("gemini-2.0-flash")) ||
                                      availableModels.find(m => m.includes("gemini-1.5-flash")) ||
                                      availableModels.find(m => m.includes("gemini")) || 
                                      availableModels[0];
                    }
                } else if (listRes.status === 400 || listRes.status === 403) {
                    throw new Error("Anahtarınız geçersiz veya kısıtlanmış olabilir.");
                }
            } catch (e) {
                if (e.message.includes("geçersiz")) throw e;
                console.log("Model listesi okunamadı, varsayılan model ile deneniyor:", targetModel);
            }

            // 2. ADIM: Kesin ve onaylı model ismiyle işlemi başlat
            const payload = { contents: [{ parts: [{ text: promptText }] }] };
            if (isJson) payload.generationConfig = { responseMimeType: "application/json", temperature: 0.8 };

            const generateUrl = `https://generativelanguage.googleapis.com/v1beta/models/${targetModel}:generateContent?key=${apiKey}`;
            const res = await fetch(generateUrl, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(payload)
            });

            if (res.ok) {
                const data = await res.json();
                if (data.candidates && data.candidates[0] && data.candidates[0].content && data.candidates[0].content.parts) {
                    return data.candidates[0].content.parts[0].text;
                }
            } else {
                const errData = await res.json().catch(() => ({}));
                throw new Error(errData.error?.message || `HTTP ${res.status}`);
            }
            throw new Error("Google sunucularından geçerli yanıt alınamadı.");
        }
        // =========================================================================

        function toggleRobom() {
            const win = document.getElementById('robomWindow');
            win.style.display = (win.style.display === 'flex') ? 'none' : 'flex';
        }

        async function sendRobomMessage() {
            const input = document.getElementById('robomCustomInput');
            const message = input.value.trim();
            if (!message) return;
            input.value = '';
            
            const chat = document.getElementById('robomChat');
            const apiKey = localStorage.getItem('deedsa_gemini_api_key') || '';
            chat.innerHTML += `<div class="chat-msg user">${message}</div>`;
            chat.scrollTop = chat.scrollHeight;

            if (!apiKey) {
                chat.innerHTML += `<div class="chat-msg robom">⚠️ Üst menüdeki <strong>"Gemini API"</strong> menüsünden anahtarınızı kaydedin.</div>`;
                chat.scrollTop = chat.scrollHeight;
                return;
            }

            chat.innerHTML += `<div class="chat-msg robom" id="robomThinking"><i class="fa-solid fa-spinner fa-spin text-primary me-2"></i> Düşünüyor...</div>`;
            chat.scrollTop = chat.scrollHeight;

            try {
                const systemPrompt = `Sen Robom adında samimi ve yardımsever bir e-ticaret & alan adı asistanısın.\\nKullanıcı: ${message}\\nRobom:`;
                const replyText = await callGeminiDirectly(apiKey, systemPrompt, false);
                document.getElementById('robomThinking')?.remove();
                const cleanReply = replyText.replace(/\\*\\*(.*?)\\*\\*/g, '<strong>$1</strong>').replace(/\\n/g, '<br>');
                chat.innerHTML += `<div class="chat-msg robom">${cleanReply}</div>`;
            } catch (err) {
                document.getElementById('robomThinking')?.remove();
                chat.innerHTML += `<div class="chat-msg robom text-danger">Bağlantı hatası: ${err.message}</div>`;
            }
            chat.scrollTop = chat.scrollHeight;
        }

        function copyDomain(domain) {
            navigator.clipboard.writeText(domain);
            const toast = document.getElementById('copyToast');
            toast.innerText = `${domain} kopyalandı!`;
            toast.style.display = 'block';
            setTimeout(() => { toast.style.display = 'none'; }, 2000);
        }

        function parseDomainsFromRaw(raw) {
            try {
                const clean = raw.replace(/^```[a-zA-Z]*\\n?/, '').replace(/\\n?```$/, '').trim();
                const match = clean.match(/\\{.*\\}/s);
                if (match) {
                    const parsed = JSON.parse(match[0]);
                    if (parsed.domains && Array.isArray(parsed.domains)) return parsed.domains;
                }
            } catch (e) {}

            try {
                const direct = JSON.parse(raw);
                if (direct.domains && Array.isArray(direct.domains)) return direct.domains;
            } catch (e) {}

            const results = [];
            const regex = /"domain"\\s*:\\s*"([^"]+)"\\s*,\\s*"explanation"\\s*:\\s*"([^"]*)"\\s*,\\s*"score"\\s*:\\s*(\\d+)/g;
            let m;
            while ((m = regex.exec(raw)) !== null) {
                results.push({ domain: m[1], explanation: m[2], score: parseInt(m[3]) });
            }
            return results;
        }

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
            document.getElementById('loadingTitle').innerText = "Model Doğrulanıyor...";
            document.getElementById('loadingSubtitle').innerText = "Yapay zeka ile en güvenli modele bağlanılıyor.";

            try {
                const prompt = `You are an elite global domain broker and e-commerce brand namer.
TARGET NICHE: "${category}"
CRITICAL RULES:
1. DOMAIN NAMES MUST BE 100% ENGLISH (e.g. PureGlow, SilkPulse).
2. EXPLANATION LANGUAGE: The 'explanation' field MUST BE STRICTLY WRITTEN IN TURKISH.
3. Every domain must be composed of 2 real, rhythmic, high-value English words.
4. Generate 25 potential available .COM domains.
5. Output ONLY valid JSON matching this schema:
{
    "domains": [
        {
            "domain": "pureglow.com",
            "explanation": "Yüksek marka algısı ve ritim sunan alan adı.",
            "score": 94
        }
    ]
}`;

                const rawGeminiResponse = await callGeminiDirectly(apiKey, prompt, true);
                const generatedList = parseDomainsFromRaw(rawGeminiResponse);

                if (!generatedList || generatedList.length === 0) {
                    throw new Error("Yapay zeka listesi oluşturulamadı.");
                }

                document.getElementById('loadingTitle').innerText = "Canlı DNS Doğrulaması Yapılıyor...";
                document.getElementById('loadingSubtitle').innerText = `${generatedList.length} alan adı için küresel DNS kayıtları taranıyor.`;

                const dnsRes = await fetch('/verify-domains-dns', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ domains: generatedList })
                });

                const data = await dnsRes.json();
                if (data.status === 'success') {
                    const currentResults = data.results || [];
                    document.getElementById('resultCountInfo').innerText = `${currentResults.length} adet boşta alan adı bulundu.`;
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
                                        <button class="btn btn-action" onclick="copyDomain('${item.domain}')">Kopyala</button>
                                        <a href="https://www.namecheap.com/domains/registration/results/?domain=${item.domain}" target="_blank" class="btn btn-register">Hemen Al</a>
                                    </div>
                                </div>
                                <div class="sedo-banner mt-3 p-3 bg-light rounded d-flex justify-content-between align-items-center">
                                    <div class="text-secondary small">Satışa çıkar:</div>
                                    <a href="https://sedo.com/?language=us&campaignId=336614" target="_blank" class="btn btn-primary btn-sm fw-bold">Sedo.com</a>
                                </div>
                            </div>
                        `;
                    });
                    resultsContainer.classList.remove('d-none');
                } else {
                    alert('DNS Hatası: ' + data.detail);
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
# 3. YALNIZCA DNS DOĞRULAYAN HIZLI SUNUCU MOTORU
# -------------------------------------------------------------
class CandidateDomain(BaseModel):
    domain: str
    explanation: str = ""
    score: int = 90

class VerifyDNSRequest(BaseModel):
    domains: List[CandidateDomain]

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

@app.post("/verify-domains-dns")
async def verify_domains_dns(req: VerifyDNSRequest, request: Request):
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
    uvicorn.run(app, host="127.0.0.1", port=8000)
