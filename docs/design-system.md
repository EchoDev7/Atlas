# Atlas VPN Panel — Design System

> A warm minimalist spatial UI design system with Cloud Dancer aesthetics, glassmorphism effects, and soft shadows.

---

## 🎨 Design Philosophy

Atlas VPN Panel follows a **Warm Minimalist Spatial UI** approach with these core principles:

- **Simplicity First**: Clean, uncluttered interfaces with purposeful whitespace
- **Natural Warmth**: Soft, organic color palette inspired by nature
- **Spatial Depth**: Glassmorphism and layered shadows create floating, dimensional elements
- **Tactile Interactions**: Smooth transitions and subtle hover states
- **Accessibility**: High contrast ratios and readable typography

---

## 🌈 Color Palette

### Primary Colors

#### Cloud (Base/Background)
Warm off-white tones for backgrounds and surfaces.

```css
cloud-50:  #fdfcfb  /* Lightest - subtle highlights */
cloud-100: #faf9f7  /* Base background */
cloud-200: #f5f3ef  /* Elevated surfaces */
cloud-300: #f0ede7
cloud-400: #ebe7df
cloud-500: #e6e1d7  /* Cloud Dancer base */
cloud-600: #d4cfc5
cloud-700: #c2bdb3
cloud-800: #b0aba1
cloud-900: #9e998f  /* Darkest */
```

**Usage**: Page backgrounds, card surfaces, subtle dividers

---

#### Sage (Primary Brand)
Natural green tones for primary actions and branding.

```css
sage-50:  #f6f7f6  /* Lightest backgrounds */
sage-100: #e3e8e3
sage-200: #c7d1c7
sage-300: #a8b9a8
sage-400: #8ba18b
sage-500: #6d896d  /* Primary brand color */
sage-600: #5a7159  /* Primary hover */
sage-700: #475947  /* Primary active */
sage-800: #364136  /* Dark text */
sage-900: #252925  /* Darkest text */
```

**Usage**: Primary buttons, links, icons, focus states, navigation

---

### Accent Colors

#### Sky (Informational)
Soft blue tones for informational elements.

```css
sky-50:  #f4f8fb
sky-100: #e3eef6
sky-200: #c7ddec
sky-300: #abcce3
sky-400: #8fbbd9
sky-500: #73aad0  /* Info base */
sky-600: #5a8fb8
sky-700: #47749a
sky-800: #36597c
sky-900: #253e5e
```

**Usage**: Info messages, status indicators, secondary icons

---

#### Honey (Warning/Highlight)
Warm golden tones for warnings and highlights.

```css
honey-50:  #fdfaf4
honey-100: #f9f0e3
honey-200: #f3e1c7
honey-300: #ecd2ab
honey-400: #e6c38f
honey-500: #dfb473  /* Warning base */
honey-600: #d6a04f
honey-700: #b88638
honey-800: #8a6529
honey-900: #5c431b
```

**Usage**: Warning messages, pending states, highlights

---

#### Terracotta (Error/Destructive)
Earthy red tones for errors and destructive actions.

```css
terracotta-50:  #fdf6f4
terracotta-100: #f9e8e3
terracotta-200: #f3d1c7
terracotta-300: #ecb9ab
terracotta-400: #e6a28f
terracotta-500: #df8a73  /* Error base */
terracotta-600: #d6724f
terracotta-700: #b85a38
terracotta-800: #8a4329  /* Error text */
terracotta-900: #5c2d1b
```

**Usage**: Error messages, delete buttons, critical alerts

---

## 🔤 Typography

### Font Family
```css
font-family: 'Inter', system-ui, -apple-system, sans-serif;
```

**Import**:
```html
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
```

### Font Weights
- **Light (300)**: Subtle labels, secondary text
- **Regular (400)**: Body text, descriptions
- **Medium (500)**: Input fields, emphasized text
- **Semibold (600)**: Headings, labels, buttons
- **Bold (700)**: Page titles, primary headings

### Type Scale
```css
text-xs:   0.75rem  (12px)  /* Small labels, captions */
text-sm:   0.875rem (14px)  /* Body text, form labels */
text-base: 1rem     (16px)  /* Default body */
text-lg:   1.125rem (18px)  /* Subheadings */
text-xl:   1.25rem  (20px)  /* Card titles */
text-2xl:  1.5rem   (24px)  /* Section headings */
text-3xl:  1.875rem (30px)  /* Page titles */
text-4xl:  2.25rem  (36px)  /* Hero titles */
```

---

## 🎭 Effects & Shadows

### Glassmorphism

#### Glass Card (Standard)
```css
.glass-card {
    background: rgba(255, 255, 255, 0.7);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.3);
}
```
**Usage**: Content cards, modals, panels

---

#### Glass Card Strong
```css
.glass-card-strong {
    background: rgba(255, 255, 255, 0.85);
    backdrop-filter: blur(24px);
    -webkit-backdrop-filter: blur(24px);
    border: 1px solid rgba(255, 255, 255, 0.4);
}
```
**Usage**: Navigation bars, sticky headers, important containers

---

#### Glass Input
```css
.input-glass {
    background: rgba(255, 255, 255, 0.6);
    backdrop-filter: blur(8px);
    -webkit-backdrop-filter: blur(8px);
    border: 1.5px solid rgba(109, 137, 109, 0.15);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.input-glass:focus {
    background: rgba(255, 255, 255, 0.8);
    border-color: rgba(109, 137, 109, 0.4);
    box-shadow: 0 0 0 3px rgba(109, 137, 109, 0.08),
                0 4px 16px -2px rgba(0, 0, 0, 0.06);
    outline: none;
}
```
**Usage**: Text inputs, textareas, select fields

---

### Soft Shadows

```css
/* Subtle elevation */
shadow-soft: 0 2px 8px -1px rgba(0, 0, 0, 0.04),
             0 4px 16px -2px rgba(0, 0, 0, 0.06);

/* Medium elevation */
shadow-soft-lg: 0 4px 16px -2px rgba(0, 0, 0, 0.06),
                0 8px 32px -4px rgba(0, 0, 0, 0.08);

/* High elevation */
shadow-soft-xl: 0 8px 32px -4px rgba(0, 0, 0, 0.08),
                0 16px 64px -8px rgba(0, 0, 0, 0.10);

/* Glow effects */
shadow-glow-sage: 0 0 20px rgba(109, 137, 109, 0.15),
                  0 0 40px rgba(109, 137, 109, 0.08);

shadow-glow-sky: 0 0 20px rgba(115, 170, 208, 0.15),
                 0 0 40px rgba(115, 170, 208, 0.08);
```

---

## 🔘 Components

### Buttons

#### Primary Button
```css
.btn-primary {
    background: linear-gradient(135deg, #6d896d 0%, #5a7159 100%);
    color: white;
    font-weight: 600;
    padding: 0.875rem 1.5rem;
    border-radius: 0.75rem;
    box-shadow: 0 4px 16px -2px rgba(0, 0, 0, 0.06),
                0 8px 32px -4px rgba(0, 0, 0, 0.08);
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.btn-primary:hover:not(:disabled) {
    background: linear-gradient(135deg, #5a7159 0%, #475947 100%);
    transform: translateY(-1px);
    box-shadow: 0 8px 24px -4px rgba(109, 137, 109, 0.3);
}

.btn-primary:active:not(:disabled) {
    transform: translateY(0);
}
```

---

#### Secondary Button
```css
.btn-secondary {
    background: rgba(115, 170, 208, 0.1);
    color: #36597c;
    border: 1.5px solid rgba(115, 170, 208, 0.2);
    font-weight: 500;
    padding: 0.875rem 1.5rem;
    border-radius: 0.75rem;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}

.btn-secondary:hover:not(:disabled) {
    background: rgba(115, 170, 208, 0.15);
    border-color: rgba(115, 170, 208, 0.3);
    transform: translateY(-1px);
}
```

---

### Input Fields

```html
<div class="relative">
    <label class="block text-sm font-semibold text-sage-800 mb-2">
        Username
    </label>
    <input 
        type="text"
        class="input-glass block w-full pl-12 pr-4 py-3.5 rounded-xl 
               text-sage-900 placeholder-sage-400 text-sm font-medium"
        placeholder="Enter your username"
    >
</div>
```

---

### Cards

```html
<div class="glass-card rounded-2xl p-6 shadow-soft-lg">
    <h3 class="text-xl font-bold text-sage-900 mb-2">Card Title</h3>
    <p class="text-sage-700">Card content goes here...</p>
</div>
```

---

## 🎬 Animations

### Transitions
```css
/* Smooth standard transition */
.smooth-transition {
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
}
```

### Keyframe Animations

```css
/* Fade in */
@keyframes fadeIn {
    0% { opacity: 0; }
    100% { opacity: 1; }
}
.animate-fade-in { animation: fadeIn 0.5s ease-out; }

/* Slide up */
@keyframes slideUp {
    0% { transform: translateY(20px); opacity: 0; }
    100% { transform: translateY(0); opacity: 1; }
}
.animate-slide-up { animation: slideUp 0.4s ease-out; }

/* Scale in */
@keyframes scaleIn {
    0% { transform: scale(0.95); opacity: 0; }
    100% { transform: scale(1); opacity: 1; }
}
.animate-scale-in { animation: scaleIn 0.3s ease-out; }

/* Float (for icons/badges) */
@keyframes float {
    0%, 100% { transform: translateY(0px); }
    50% { transform: translateY(-10px); }
}
.floating { animation: float 6s ease-in-out infinite; }
```

---

## 📐 Spacing & Layout

### Border Radius
```css
rounded-lg:   0.5rem   (8px)   /* Small elements */
rounded-xl:   0.75rem  (12px)  /* Inputs, buttons */
rounded-2xl:  1rem     (16px)  /* Cards */
rounded-3xl:  1.5rem   (24px)  /* Large containers */
```

### Spacing Scale
```css
space-1:  0.25rem  (4px)
space-2:  0.5rem   (8px)
space-3:  0.75rem  (12px)
space-4:  1rem     (16px)
space-5:  1.25rem  (20px)
space-6:  1.5rem   (24px)
space-8:  2rem     (32px)
space-10: 2.5rem   (40px)
```

---

## 🎯 Usage Guidelines

### Do's ✅
- Use `cloud-100` as the base page background
- Apply glassmorphism to elevated surfaces (cards, modals, navigation)
- Use `sage-500` for primary actions and brand elements
- Maintain consistent spacing using the spacing scale
- Use soft shadows for depth, not harsh borders
- Keep animations subtle and purposeful
- Use `font-semibold` for interactive elements (buttons, labels)

### Don'ts ❌
- Don't use pure white (`#ffffff`) — use `cloud-50` instead
- Don't use harsh black — use `sage-900` for dark text
- Don't mix glassmorphism with solid backgrounds on the same level
- Don't use multiple accent colors in a single component
- Don't create custom shadows — use the predefined soft shadows
- Don't use transitions longer than 0.3s for UI interactions

---

## 🔧 Implementation

### Tailwind Config (CDN)
```javascript
tailwind.config = {
    theme: {
        extend: {
            colors: {
                cloud: { /* ... */ },
                sage: { /* ... */ },
                sky: { /* ... */ },
                honey: { /* ... */ },
                terracotta: { /* ... */ }
            },
            boxShadow: {
                'soft': '0 2px 8px -1px rgba(0, 0, 0, 0.04), 0 4px 16px -2px rgba(0, 0, 0, 0.06)',
                'soft-lg': '0 4px 16px -2px rgba(0, 0, 0, 0.06), 0 8px 32px -4px rgba(0, 0, 0, 0.08)',
                'soft-xl': '0 8px 32px -4px rgba(0, 0, 0, 0.08), 0 16px 64px -8px rgba(0, 0, 0, 0.10)',
            }
        }
    }
}
```

### Base Template
All pages should extend from `/frontend/templates/base.html` which includes:
- Tailwind CSS configuration
- Inter font import
- Glassmorphism CSS classes
- Button styles
- Animation keyframes

---

## 📱 Responsive Design

### Breakpoints
```css
sm:  640px   /* Small tablets */
md:  768px   /* Tablets */
lg:  1024px  /* Laptops */
xl:  1280px  /* Desktops */
2xl: 1536px  /* Large screens */
```

### Mobile-First Approach
- Design for mobile first, enhance for larger screens
- Use responsive grid: `grid-cols-1 md:grid-cols-2 lg:grid-cols-3`
- Stack navigation items vertically on mobile
- Reduce padding/spacing on smaller screens

---

## 🎨 Example Implementations

### Login Page
See: `/frontend/templates/login.html`
- Glassmorphism card with floating animation
- Soft background gradients (blurred circles)
- Input fields with glass effect
- Primary sage button with gradient

### Dashboard
See: `/frontend/dashboard.html`
- Glass navigation bar (sticky)
- Stat cards with glassmorphism
- Color-coded icons (sage, sky, honey)
- Soft shadows for depth

---

## 🚀 Future Additions

As the project grows, maintain consistency by:
1. Using the defined color palette
2. Applying glassmorphism to elevated surfaces
3. Using soft shadows for depth
4. Keeping animations smooth and subtle
5. Following the typography scale
6. Maintaining warm, natural aesthetics

---

**Version**: 1.0.0  
**Last Updated**: Phase 1 (Authentication)  
**Maintained by**: Atlas VPN Panel Team
