/* ============================================================
   SANTHOSH P — PORTFOLIO
   Interactions & UI logic
   ============================================================ */

(function () {
  'use strict';

  /* ---------- Preloader ---------- */
  const preloader = document.getElementById('preloader');
  window.addEventListener('load', () => {
    setTimeout(() => preloader && preloader.classList.add('hidden'), 600);
  });
  setTimeout(() => preloader && preloader.classList.add('hidden'), 3000);

  /* ---------- Navbar scroll state ---------- */
  const navbar = document.getElementById('navbar');
  const onScrollNav = () => navbar && navbar.classList.toggle('scrolled', window.scrollY > 30);
  onScrollNav();
  window.addEventListener('scroll', onScrollNav, { passive: true });

  /* ---------- Mobile nav toggle ---------- */
  const navToggle = document.getElementById('navToggle');
  const navLinks = document.getElementById('navLinks');
  navToggle.addEventListener('click', () => {
    navToggle.classList.toggle('open');
    navLinks.classList.toggle('open');
  });
  navLinks.querySelectorAll('.nav-link').forEach((link) => {
    link.addEventListener('click', () => {
      navToggle.classList.remove('open');
      navLinks.classList.remove('open');
    });
  });

  /* ---------- Active nav link on scroll ---------- */
  const sections = document.querySelectorAll('section[id]');
  const linkEls = document.querySelectorAll('.nav-link');
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          linkEls.forEach((l) => l.classList.toggle('active', l.getAttribute('href') === '#' + entry.target.id));
        }
      });
    },
    { rootMargin: '-45% 0px -50% 0px' }
  );
  sections.forEach((s) => observer.observe(s));

  /* ---------- Reveal on scroll ---------- */
  const revealEls = document.querySelectorAll('.reveal');
  const revealObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          revealObserver.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.12, rootMargin: '0px 0px -40px 0px' }
  );
  revealEls.forEach((el) => revealObserver.observe(el));

  /* ---------- Skill bars animate ---------- */
  const barObserver = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const bar = entry.target;
          bar.style.width = bar.getAttribute('style') ? bar.style.getPropertyValue('--w') : '0';
          barObserver.unobserve(bar);
        }
      });
    },
    { threshold: 0.4 }
  );
  document.querySelectorAll('.bar i').forEach((bar) => barObserver.observe(bar));

  /* ---------- Typing effect for hero role ---------- */
  const roleEl = document.querySelector('.hero-role');
  if (roleEl) {
    const phrases = [
      'Full-Stack Web Developer',
      'PHP / Laravel Engineer',
      'Cybersecurity Enthusiast',
      'Ethical Hacker (CEH v12)',
    ];
    let p = 0, c = 0, deleting = false;

    const type = () => {
      const word = phrases[p];
      roleEl.textContent = word.slice(0, c);
      let delay = deleting ? 40 : 75;

      if (!deleting && c === word.length) {
        delay = 1800;
        deleting = true;
      } else if (deleting && c === 0) {
        deleting = false;
        p = (p + 1) % phrases.length;
        delay = 400;
      }
      c += deleting ? -1 : 1;
      setTimeout(type, delay);
    };
    type();
  }

  /* ---------- Footer year ---------- */
  const yearEl = document.getElementById('year');
  if (yearEl) yearEl.textContent = new Date().getFullYear();
})();
