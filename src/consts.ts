/**
 * Site-wide constants and the single source of truth for identity data.
 * Do NOT invent facts here — anything Brian must supply is marked TODO.
 */

export const SITE = {
  title: 'briancgx',
  domain: 'briancgx.me',
  url: 'https://briancgx.me',
  description:
    'Writeups y notas de briancgx — AI Security Researcher @ Straiker y Red Team Operator. Máquinas, hacking práctico y seguridad de sistemas agénticos.',
  lang: 'es',
  locale: 'es_MX',
} as const;

export const IDENTITY = {
  handle: 'briancgx',
  role: 'AI Security Researcher @ Straiker',
  role2: 'Red Team Operator',
  team: 'Straiker',
  location: 'México',
  focus: 'Le gusta resolver máquinas y el hacking práctico.',
  email: 'contact@briancgx.me',
  // Offensive + AI stack shown in the whoami card.
  stack: {
    offensive: [
      'Red teaming',
      'Web / infra exploitation',
      'Pivoting & tunneling',
      'Privilege escalation',
    ],
    ai: [
      'LLM red teaming',
      'Prompt injection',
      'Agentic tool-use abuse',
      'AI security research',
    ],
  },
} as const;

export const SOCIAL = {
  github: 'https://github.com/briancgx',
  linkedin: 'https://www.linkedin.com/in/briancgx',
  instagram: 'https://instagram.com/briancgx',
  htb: 'https://app.hackthebox.com/users/1406402',
  email: 'contact@briancgx.me',
} as const;

// Real CV (email corregido a contact@briancgx.me) en public/cv/.
export const CV_PATH = '/cv/briancgx-cv.pdf';
export const SHOW_CV = true;

// Certs reales confirmadas desde el CV de Brian (2026). Badges oficiales de
// cada emisor en /assets/certs/. Ordenadas por fecha desc.
export const SHOW_CERTS = true;
export const CERTS: {
  code: string;
  name: string;
  issuer: string;
  year: string;
  badge: string;
}[] = [
  { code: 'C-AgAIPen', name: 'Certified Agentic AI Pentester', issuer: 'The SecOps Group', year: '2026', badge: '/assets/certs/cagaipen.png' },
  { code: 'CPTS', name: 'Certified Penetration Testing Specialist', issuer: 'Hack The Box', year: '2026', badge: '/assets/certs/cpts.png' },
  { code: 'BSCP', name: 'Burp Suite Certified Practitioner', issuer: 'PortSwigger', year: '2025', badge: '/assets/certs/bscp.png' },
  { code: 'C-AI/MLPen', name: 'Certified AI/ML Pentester', issuer: 'The SecOps Group', year: '2025', badge: '/assets/certs/caimlpen.png' },
  { code: 'CRTeamer', name: 'Certified Red Teamer', issuer: 'The SecOps Group', year: '2025', badge: '/assets/certs/crteamer.png' },
  { code: 'eWPTX', name: 'Web Application Penetration Tester eXtreme', issuer: 'INE Security', year: '2025', badge: '/assets/certs/ewptx.png' },
];

// HTB Pro Labs (sin badge público — se muestran como chips de texto).
export const HTB_PRO_LABS = ['Dante', 'FullHouse', 'POO'] as const;

// Publicaciones revisadas por pares (datos verificados desde las fuentes).
export const PUBLICATIONS: {
  title: string;
  venue: string;
  year: string;
  role: string;
  url: string;
  summary: string;
  tags: string[];
}[] = [
  {
    title:
      'Counterfactual Explanation of a Classification Model for Detecting SQL Injection Attacks',
    venue: 'ICCBR 2024 · XCBR Workshop (CEUR-WS Vol-3708)',
    year: '2024',
    role: 'Primer autor',
    url: 'https://ceur-ws.org/Vol-3708/paper_05.pdf',
    summary:
      'Propone un modelo de machine learning para detectar ataques de inyección SQL y lo dota de interpretabilidad con explicaciones contrafactuales (XAI): muestra qué cambios mínimos en una consulta alterarían la decisión del modelo. Acerca la IA explicable a la seguridad de bases de datos para que los analistas entiendan y confíen en las alertas en lugar de tratarlas como una caja negra.',
    tags: ['XAI', 'Counterfactuals', 'SQL Injection', 'Machine Learning'],
  },
  {
    title:
      'A Deep Learning Approach for Automated Identification of Triatoma infestans Using YOLOv8',
    venue: 'JAICA · Vol. 2 (2)',
    year: '2024',
    role: 'Coautor',
    url: 'https://zenodo.org/records/14976415',
    summary:
      'Aplica visión por computadora con YOLOv8 para identificar automáticamente a Triatoma infestans, principal vector de la enfermedad de Chagas, entrenando con 91 imágenes etiquetadas y 9,100 aumentadas. Alcanza un mAP@50 de 0.9588 y distingue al vector de insectos similares sin falsos positivos, sentando la base para vigilancia entomológica en sistemas móviles y embebidos.',
    tags: ['YOLOv8', 'Computer Vision', 'Chagas', 'Vector Surveillance'],
  },
];

// Backend endpoint for the agentic CTF challenge. Overridable via env.
export const AGENT_API =
  import.meta.env.PUBLIC_AGENT_API ?? 'https://agent.briancgx.me';

export const NAV = [
  { label: 'Writeups', href: '/writeups' },
  { label: 'About', href: '/about' },
  { label: 'Challenge', href: '/challenge' },
] as const;

// Human labels for content facets (used across catalog + meta bars).
export const PLATFORM_LABELS: Record<string, string> = {
  htb: 'HackTheBox',
  dockerlabs: 'DockerLabs',
  tryhackme: 'TryHackMe',
};

export const DIFFICULTY_LABELS: Record<string, string> = {
  easy: 'Easy',
  medium: 'Medium',
  hard: 'Hard',
  insane: 'Insane',
};

// Offensive accent only (ops red), scaled by severity. Never emerald/yellow.
export const DIFFICULTY_CLASS: Record<string, string> = {
  easy: 'border-ops/40 text-ops',
  medium: 'border-ops/50 text-ops',
  hard: 'border-ops/70 text-ops',
  insane: 'border-ops text-ops',
};

export const LANG_LABELS: Record<string, string> = {
  es: 'ES',
  en: 'EN',
};
