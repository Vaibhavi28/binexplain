import { NavLink } from 'react-router-dom';
import { useState } from 'react';

export default function TopNav() {
  const [mobileOpen, setMobileOpen] = useState(false);
  
  const links = [
    { to: '/', label: 'Tool' },
    { to: '/docs', label: 'Docs' },
    { to: '/blog', label: 'Blog' },
    { to: '/about', label: 'About' },
    { to: '/contact', label: 'Contact' },
  ];
  
  return (
    <nav className="top-nav">
      <div className="top-nav-inner">
        <NavLink to="/" className="top-nav-logo">
          BinExplain
        </NavLink>
        
        <div className="top-nav-links">
          {links.map(link => (
            <NavLink
              key={link.to}
              to={link.to}
              className={({ isActive }) =>
                isActive ? 'top-nav-link active' : 'top-nav-link'
              }
            >
              {link.label}
            </NavLink>
          ))}
          
          <a
            href="https://github.com/Vaibhavi28/binexplain"
            target="_blank"
            rel="noopener noreferrer"
            className="top-nav-link top-nav-github"
          >
            GitHub ↗
          </a>
        </div>
        
        <button
          className="top-nav-hamburger"
          onClick={() => setMobileOpen(!mobileOpen)}
          aria-label="Toggle navigation"
        >
          {mobileOpen ? '✕' : '☰'}
        </button>
      </div>
      
      {mobileOpen && (
        <div className="top-nav-mobile">
          {links.map(link => (
            <NavLink
              key={link.to}
              to={link.to}
              className="top-nav-mobile-link"
              onClick={() => setMobileOpen(false)}
            >
              {link.label}
            </NavLink>
          ))}
          
          <a
            href="https://github.com/Vaibhavi28/binexplain"
            target="_blank"
            rel="noopener noreferrer"
            className="top-nav-mobile-link"
            onClick={() => setMobileOpen(false)}
          >
            GitHub ↗
          </a>
        </div>
      )}
    </nav>
  );
}
