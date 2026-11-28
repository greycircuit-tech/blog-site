/* ==========================================================================
   GREY CIRCUIT TECHNOLOGIES — BLOG FRONTEND INTERACTION ENGINE (script.js)
   Zero-dependency Vanilla ES6+ runtime for blogs.greycircuit.tech.
   ========================================================================== */

(() => {
  'use strict';

  const prefersReducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  const isFinePointer = window.matchMedia('(pointer: fine)').matches;

  /* ------------------------------------------------------------------------
     1. MAGNETIC MICRO-INTERACTIONS (NATIVE BROWSER CURSOR RESTORED)
     ------------------------------------------------------------------------ */
  function initMagneticInteractions() {
    if (prefersReducedMotion) return;

    document.querySelectorAll('[data-magnetic]').forEach((el) => {
      el.addEventListener('mousemove', (e) => {
        const rect = el.getBoundingClientRect();
        const dx = (e.clientX - (rect.left + rect.width / 2)) * 0.22;
        const dy = (e.clientY - (rect.top + rect.height / 2)) * 0.22;
        el.style.transform = `translate3d(${dx}px, ${dy}px, 0)`;
      });
      el.addEventListener('mouseleave', () => {
        el.style.transform = '';
      });
    });
  }

  /* ------------------------------------------------------------------------
     2. DYNAMIC ISLAND HEADER, DROPDOWN & MOBILE DRAWER NAVIGATION
     ------------------------------------------------------------------------ */
  function initNavigation() {
    const nav = document.getElementById('site-nav');
    if (!nav) return;

    // Dropdown menu toggle
    const dropdowns = nav.querySelectorAll('.nav-dropdown');
    const closeAllDropdowns = () => {
      dropdowns.forEach((dd) => {
        dd.classList.remove('is-open');
        dd.querySelector('.nav-dropdown-trigger')?.setAttribute('aria-expanded', 'false');
      });
    };

    dropdowns.forEach((dd) => {
      const trigger = dd.querySelector('.nav-dropdown-trigger');
      trigger?.addEventListener('click', (e) => {
        e.stopPropagation();
        const isOpen = dd.classList.toggle('is-open');
        trigger.setAttribute('aria-expanded', String(isOpen));
      });
    });

    document.addEventListener('click', (e) => {
      if (!e.target.closest('.nav-dropdown')) closeAllDropdowns();
    });

    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') closeAllDropdowns();
    });

    // Scroll behavior: compact island + hide on fast downward scroll
    let lastScrollY = window.scrollY;
    window.addEventListener('scroll', () => {
      const currentY = window.scrollY;
      const isScrolled = currentY > 40;
      nav.classList.toggle('is-scrolled', isScrolled);
      const widget = document.getElementById('reader-profile-widget');
      if (widget) widget.classList.toggle('is-scrolled', isScrolled);

      if (currentY > 280 && currentY - lastScrollY > 14) {
        nav.classList.add('is-hidden');
        if (widget) widget.classList.add('is-hidden');
        closeAllDropdowns();
      } else if (lastScrollY - currentY > 10 || currentY < 120) {
        nav.classList.remove('is-hidden');
        if (widget) widget.classList.remove('is-hidden');
      }
      lastScrollY = currentY;
    }, { passive: true });

    // Mobile slide-out drawer
    const drawerToggle = document.getElementById('mobile-drawer-toggle');
    const drawerClose = document.getElementById('mobile-drawer-close');
    const drawer = document.getElementById('mobile-drawer');
    const backdrop = document.getElementById('mobile-drawer-backdrop');

    if (drawerToggle && drawer && backdrop) {
      const setDrawerState = (open) => {
        drawer.classList.toggle('is-open', open);
        drawer.setAttribute('aria-hidden', String(!open));
        drawerToggle.setAttribute('aria-expanded', String(open));
        backdrop.hidden = !open;
        document.body.style.overflow = open ? 'hidden' : '';
      };

      drawerToggle.addEventListener('click', () => setDrawerState(true));
      drawerClose?.addEventListener('click', () => setDrawerState(false));
      backdrop.addEventListener('click', () => setDrawerState(false));
      drawer.querySelectorAll('a').forEach((link) => {
        link.addEventListener('click', () => setDrawerState(false));
      });
    }
  }

  /* ------------------------------------------------------------------------
     3. FLOATING BACK TO TOP CONTROL
     ------------------------------------------------------------------------ */
  function initBackToTop() {
    if (window.__GCT_BACK_TO_TOP_INIT__) return;
    window.__GCT_BACK_TO_TOP_INIT__ = true;

    let btn = document.getElementById('btn-back-to-top');
    if (!btn) {
      btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'back-to-top';
      btn.id = 'btn-back-to-top';
      btn.setAttribute('aria-label', 'Back to top');
      btn.setAttribute('title', 'Back to top');
      btn.innerHTML = `
        <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
          <polyline points="18 15 12 9 6 15"></polyline>
        </svg>
      `;
      document.body.appendChild(btn);
    }

    const SCROLL_THRESHOLD = 400;
    let ticking = false;

    const updateVisibility = () => {
      const scrollY = window.scrollY || document.documentElement.scrollTop;
      if (scrollY > SCROLL_THRESHOLD) {
        btn.classList.add('is-visible');
      } else {
        btn.classList.remove('is-visible');
      }
      ticking = false;
    };

    window.addEventListener('scroll', () => {
      if (!ticking) {
        window.requestAnimationFrame(updateVisibility);
        ticking = true;
      }
    }, { passive: true });

    btn.addEventListener('click', () => {
      window.scrollTo({
        top: 0,
        behavior: prefersReducedMotion ? 'auto' : 'smooth'
      });
    });

    // Initial check
    updateVisibility();
  }

  /* ------------------------------------------------------------------------
     4. ACCESSIBLE SKIP TO MAIN CONTENT ENHANCEMENT
     ------------------------------------------------------------------------ */
  function initSkipLinkAccessibility() {
    const skipLink = document.querySelector('.skip-link');
    const mainContent = document.getElementById('main-content');
    if (!skipLink || !mainContent) return;

    if (!mainContent.hasAttribute('tabindex')) {
      mainContent.setAttribute('tabindex', '-1');
    }

    skipLink.addEventListener('click', (e) => {
      mainContent.focus({ preventScroll: false });
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => {
      initMagneticInteractions();
      initNavigation();
      initBackToTop();
      initSkipLinkAccessibility();
    });
  } else {
    initMagneticInteractions();
    initNavigation();
    initBackToTop();
    initSkipLinkAccessibility();
  }
})();
