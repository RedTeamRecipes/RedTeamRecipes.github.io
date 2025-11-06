---
layout: page
title: Hall of Fame
icon: fa-solid fa-crown
order: 5
---

<style>
/* ===== leaderboard look (dark, compact, clean) ===== */
:root{
  --row-bg: #111317;
  --row-bg-alt: #0e1014;
  --row-hover: #171a20;
  --thead-bg: #1a1e25;
  --ink: #e8eaf0;
  --muted: #a8afba;
  --accent: #37f;
  --border: #232733;
  --radius: 10px;
}

.hof-board{
  margin: 1.5rem auto;
  max-width: 1100px;
  color: var(--ink);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
  box-shadow: 0 8px 28px rgba(0,0,0,.35);
}

.hof-table{
  width: 100%;
  border-collapse: collapse;
  font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto, Helvetica, Arial;
  font-size: 0.98rem;
}
.hof-table thead th{
  text-align: left;
  padding: .9rem 1rem;
  background: var(--thead-bg);
  color: var(--muted);
  font-weight: 700;
  letter-spacing: .02em;
  border-bottom: 1px solid var(--border);
}
.hof-table tbody tr{ background: var(--row-bg); }
.hof-table tbody tr:nth-child(even){ background: var(--row-bg-alt); }
.hof-table tbody tr:hover{ background: var(--row-hover); }

.hof-table td{
  padding: .85rem 1rem;
  border-bottom: 1px solid var(--border);
  vertical-align: middle;
  white-space: nowrap;
}

/* Rank bubble */
.rank{
  width: 36px; text-align: center; font-weight: 800; color: var(--ink);
  opacity: .9;
}

/* Name cell with avatar */
.name{
  display: flex; align-items: center; gap: .75rem; min-width: 240px;
}
.name .avatar{
  width: 36px; height: 36px; border-radius: 50%; object-fit: cover;
  box-shadow: 0 0 0 2px #000, 0 0 0 3px #2a2f3a;
}
.name .nick{
  font-weight: 700;
}
.name .nick a{
  color: var(--ink); text-decoration: none; border-bottom: 1px dotted transparent;
}
.name .nick a:hover{ color: var(--accent); border-color: var(--accent); }

/* Posts badge */
.posts{
  font-weight: 700; color: var(--ink);
}
.posts .chip{
  display: inline-block; padding: .2rem .55rem; border-radius: 999px;
  background: rgba(255,255,255,.05); border: 1px solid var(--border);
}

/* Country flag (emoji or tiny png) */
.country{
  display: inline-flex; align-items: center; gap: .5rem;
  color: var(--muted);
}
.country img{ width: 20px; height: 14px; border-radius: 2px; box-shadow: 0 0 0 1px rgba(0,0,0,.35); }

/* Contact pills */
.contact a{
  display: inline-block; margin-right: .35rem; padding: .32rem .6rem;
  border-radius: 999px; text-decoration: none; font-weight: 600;
  background: rgba(255,255,255,.05); border: 1px solid var(--border); color: var(--muted);
  transition: transform .12s ease, color .12s ease, border-color .12s ease;
}
.contact a:hover{ transform: translateY(-2px); color: var(--ink); border-color: var(--accent); }

/* Mobile: allow horizontal scroll instead of squishing */
.hof-wrap{ overflow-x: auto; }
.hof-table{ min-width: 820px; }

</style>

<div class="hof-board">
  <div class="hof-wrap">
    <table class="hof-table">
      <thead>
        <tr>
          <th style="width:60px;">Rank</th>
          <th>Name</th>
          <th>Number of Posts</th>
          <th>Country</th>
          <th>Contact</th>
        </tr>
      </thead>
      <tbody>
        <!-- Row template:
          <tr>
            <td class="rank">#</td>
            <td class="name">
              <img class="avatar" src="/assets/img/avatars/NAME.png" alt="NAME avatar">
              <span class="nick"><a href="/about/#NAME">NAME</a></span>
            </td>
            <td class="posts"><span class="chip">##</span></td>
            <td class="country"><img src="/assets/img/flags/xx.png" alt=""> COUNTRY</td>
            <td class="contact">
              <a href="https://github.com/NAME" target="_blank" rel="noopener">GitHub</a>
              <a href="https://x.com/NAME" target="_blank" rel="noopener">X</a>
            </td>
          </tr>
        -->

      </tbody>
    </table>
  </div>
</div>
