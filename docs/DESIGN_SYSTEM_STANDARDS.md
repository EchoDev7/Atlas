# Atlas VPN Panel - Design System Standards (PERMANENT)

**این استانداردها برای تمام صفحات و کامپوننت‌های آینده پروژه الزامی است.**

---

## 🎨 رنگ‌بندی اصلی (بر اساس لوگو)

### Light Mode (حالت روشن)
```css
/* Primary Brand Colors - از لوگو گرفته شده */
Primary: Cyan-600 (#0891b2)
Secondary: Teal-600 (#0d9488)
Accent: Cyan-500 (#06b6d4)

/* Backgrounds */
Page Background: Slate-50 (#f8fafc)
Card Background: White (#ffffff) با glassmorphism
Blur Circles: Cyan-100/40, Teal-100/40

/* Text Colors */
Headings: Slate-900 (#0f172a)
Body Text: Slate-700 (#334155)
Muted Text: Slate-600 (#475569)
Brand Text: Cyan-600 (#0891b2)

/* Interactive Elements */
Buttons: Gradient from Cyan-500 to Teal-500
Inputs Border: Cyan-200 (#a5f3fc)
Inputs Focus: Cyan-500 (#06b6d4)
Links: Cyan-600 (#0891b2)
```

### Dark Mode (حالت تاریک)
```css
/* Primary Brand Colors */
Primary: Cyan-400 (#22d3ee)
Secondary: Teal-400 (#2dd4bf)
Accent: Cyan-300 (#67e8f9)

/* Backgrounds */
Page Background: Slate-950 (#020617)
Card Background: White/5 با glassmorphism
Blur Circles: Cyan-500/10, Teal-500/10

/* Text Colors */
Headings: White (#ffffff)
Body Text: Slate-300 (#cbd5e1)
Muted Text: Slate-400 (#94a3b8)
Brand Text: Cyan-400 (#22d3ee)

/* Interactive Elements */
Buttons: Gradient from Cyan-500 to Teal-600 با glow effect
Inputs Border: Cyan-400/20
Inputs Focus: Cyan-400 با glow
Links: Cyan-400 (#22d3ee)
```

---

## 📝 تایپوگرافی

### فونت‌های اصلی
```html
<!-- در تمام صفحات این فونت‌ها را import کنید -->
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Poppins:wght@700;800;900&display=swap" rel="stylesheet">
```

### استفاده از فونت‌ها
```css
/* Body Text - همه متن‌های عادی */
font-family: 'Inter', system-ui, -apple-system, sans-serif;

/* Brand Title (کلمه Atlas) - فقط برای عنوان برند */
font-family: 'Poppins', 'Inter', system-ui, sans-serif;
class: font-display
```

### سایزها و وزن‌ها
```css
/* Headings */
H1: text-4xl md:text-5xl, font-black (900)
H2: text-2xl md:text-3xl, font-black (900)
H3: text-xl md:text-2xl, font-bold (700)

/* Body */
Large: text-lg, font-medium (500)
Normal: text-base, font-normal (400)
Small: text-sm, font-medium (500)
Tiny: text-xs, font-semibold (600)

/* Atlas Brand Title */
Login Page: text-5xl, font-black, font-display
Dashboard Header: text-2xl, font-black, font-display
با gradient: bg-gradient-to-r from-cyan-600 to-teal-600 bg-clip-text text-transparent (Light)
```

---

## 🎯 لوگو

### مسیر فایل
```
/Users/majlotfi/Desktop/Atlas/frontend/assets/images/atlas-logo.png
```

### سایزها
```html
<!-- Login Page -->
<div class="w-40 h-40">
    <img src="/assets/images/atlas-logo.png" alt="Atlas VPN Logo" class="w-full h-full object-contain drop-shadow-2xl">
</div>

<!-- Dashboard Header -->
<div class="w-14 h-14">
    <img src="/assets/images/atlas-logo.png" alt="Atlas Logo" class="w-full h-full object-contain drop-shadow-lg">
</div>

<!-- Small Icons (اگر نیاز بود) -->
<div class="w-10 h-10">
    <img src="/assets/images/atlas-logo.png" alt="Atlas" class="w-full h-full object-contain">
</div>
```

---

## 🔲 کامپوننت‌های اصلی

### Buttons (دکمه‌ها)

#### Light Mode
```html
<!-- Primary Button -->
<button class="bg-gradient-to-r from-cyan-500 to-teal-500 hover:from-cyan-600 hover:to-teal-600 text-white font-bold py-4 px-6 rounded-xl shadow-lg hover:shadow-xl transition-all duration-200 hover:scale-[1.02] active:scale-[0.98]">
    BUTTON TEXT
</button>

<!-- Secondary Button -->
<button class="bg-white border-2 border-cyan-200 text-cyan-600 hover:bg-cyan-50 hover:border-cyan-300 font-bold py-3 px-5 rounded-xl transition-all duration-200">
    BUTTON TEXT
</button>
```

#### Dark Mode
```html
<!-- Primary Button -->
<button class="btn-primary-dark text-white font-bold py-4 px-6 rounded-xl shadow-glow-cyan transition-all duration-200 hover:scale-[1.02] active:scale-[0.98]">
    BUTTON TEXT
</button>

<!-- Secondary Button -->
<button class="bg-slate-800 border-2 border-cyan-400/30 text-cyan-400 hover:bg-slate-700 hover:border-cyan-400/50 font-bold py-3 px-5 rounded-xl transition-all duration-200">
    BUTTON TEXT
</button>
```

### Inputs (فیلدهای ورودی)

#### Light Mode
```html
<input 
    type="text"
    class="w-full px-4 py-4 rounded-xl bg-white border-2 border-cyan-200 focus:border-cyan-500 focus:ring-4 focus:ring-cyan-100 text-slate-900 placeholder-slate-400 font-medium transition-all duration-200"
    placeholder="Enter text..."
>
```

#### Dark Mode
```html
<input 
    type="text"
    class="input-dark w-full px-4 py-4 rounded-xl text-white placeholder-slate-500 font-medium"
    placeholder="Enter text..."
>
```

### Cards (کارت‌ها)

#### Light Mode
```html
<div class="glass-light rounded-2xl p-6 shadow-xl">
    <!-- محتوای کارت -->
</div>
```

#### Dark Mode
```html
<div class="glass-dark rounded-2xl p-6 shadow-xl">
    <!-- محتوای کارت -->
</div>
```

### Theme Toggle Button (دکمه تغییر تم)
```html
<button 
    @click="toggleTheme()"
    class="fixed top-6 right-6 z-50 w-14 h-14 rounded-2xl theme-transition flex items-center justify-center shadow-xl hover:scale-110 active:scale-95 transition-transform duration-200"
    :class="darkMode ? 'bg-slate-800 text-cyan-400 shadow-glow-cyan' : 'bg-white text-cyan-600 shadow-lg'"
>
    <!-- آیکون‌های ماه و خورشید -->
</button>
```

---

## ✨ افکت‌ها و انیمیشن‌ها

### Glassmorphism
```css
/* Light Mode */
.glass-light {
    background: rgba(255, 255, 255, 0.9);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.5);
}

/* Dark Mode */
.glass-dark {
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.1);
}
```

### Glow Effects (فقط Dark Mode)
```css
/* Cyan Glow */
.shadow-glow-cyan {
    box-shadow: 0 0 20px rgba(34, 211, 238, 0.5), 0 0 40px rgba(34, 211, 238, 0.3);
}

/* استفاده در Tailwind Config */
boxShadow: {
    'glow-cyan': '0 0 20px rgba(34, 211, 238, 0.5), 0 0 40px rgba(34, 211, 238, 0.3)',
}
```

### Transitions
```css
.theme-transition {
    transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
}
```

### Hover Effects
```css
/* Scale on Hover */
hover:scale-105 active:scale-95 transition-transform duration-200

/* Shadow on Hover */
hover:shadow-xl transition-shadow duration-200

/* Translate on Hover */
hover:-translate-y-1 transition-transform duration-200
```

---

## 📐 Spacing & Layout

### Container
```html
<div class="max-w-7xl mx-auto px-6 lg:px-8">
    <!-- محتوا -->
</div>
```

### Grid Layouts
```html
<!-- 3 Columns -->
<div class="grid grid-cols-1 md:grid-cols-3 gap-6">
    <!-- آیتم‌ها -->
</div>

<!-- 2 Columns -->
<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
    <!-- آیتم‌ها -->
</div>
```

### Spacing Scale
```
gap-2: 0.5rem (8px)
gap-4: 1rem (16px)
gap-6: 1.5rem (24px)
gap-8: 2rem (32px)

p-4: 1rem (16px)
p-6: 1.5rem (24px)
p-8: 2rem (32px)
p-10: 2.5rem (40px)
```

---

## 🔧 Tailwind Config (الزامی برای همه صفحات)

```javascript
tailwind.config = {
    darkMode: 'class',
    theme: {
        extend: {
            fontFamily: {
                'sans': ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                'display': ['Poppins', 'Inter', 'system-ui', 'sans-serif'],
            },
            boxShadow: {
                'glow-cyan': '0 0 20px rgba(34, 211, 238, 0.5), 0 0 40px rgba(34, 211, 238, 0.3)',
            },
        }
    }
}
```

---

## 📱 Responsive Design (الزامی)

### Breakpoints
```
sm: 640px   (Mobile landscape / Small tablets)
md: 768px   (Tablets)
lg: 1024px  (Small desktops)
xl: 1280px  (Large desktops)
2xl: 1536px (Extra large screens)
```

### Mobile-First Approach
**همیشه از mobile شروع کنید و به تدریج برای صفحات بزرگ‌تر بهینه کنید.**

```html
<!-- ✅ درست -->
<div class="text-sm sm:text-base lg:text-lg">
<div class="p-4 sm:p-6 lg:p-8">
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3">

<!-- ❌ غلط -->
<div class="text-lg md:text-base sm:text-sm">
```

### Responsive Typography
```html
<!-- Headings -->
<h1 class="text-3xl sm:text-4xl lg:text-5xl">
<h2 class="text-xl sm:text-2xl lg:text-3xl">
<h3 class="text-lg sm:text-xl lg:text-2xl">

<!-- Body Text -->
<p class="text-sm sm:text-base">
<span class="text-xs sm:text-sm">

<!-- Buttons -->
<button class="text-xs sm:text-sm lg:text-base">
```

### Responsive Spacing
```html
<!-- Padding -->
<div class="p-4 sm:p-6 lg:p-8">
<div class="px-4 sm:px-6 lg:px-8">
<div class="py-4 sm:py-6 lg:py-8">

<!-- Margin -->
<div class="mb-4 sm:mb-6 lg:mb-8">
<div class="mt-6 sm:mt-8 lg:mt-10">

<!-- Gap (Grid/Flex) -->
<div class="gap-4 sm:gap-5 lg:gap-6">
<div class="space-y-4 sm:space-y-5 lg:space-y-6">
```

### Responsive Components

#### Navigation Header
```html
<nav class="sticky top-0 z-40">
    <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div class="flex justify-between items-center h-16">
            <!-- Logo -->
            <div class="w-10 h-10 sm:w-12 sm:h-12 lg:w-14 lg:h-14">
                <img src="/assets/images/atlas-logo.png" alt="Logo">
            </div>
            
            <!-- Title -->
            <span class="text-xl sm:text-2xl font-display">Atlas</span>
            
            <!-- Actions -->
            <div class="flex items-center space-x-2 sm:space-x-3 lg:space-x-4">
                <!-- Hide text on mobile, show icon -->
                <button class="px-3 py-2 sm:px-5 sm:py-2.5">
                    <span class="hidden sm:inline">LOGOUT</span>
                    <svg class="w-5 h-5 sm:hidden">...</svg>
                </button>
            </div>
        </div>
    </div>
</nav>
```

#### Cards
```html
<!-- Stat Cards -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5 lg:gap-6">
    <div class="rounded-xl sm:rounded-2xl p-5 sm:p-6">
        <div class="w-12 h-12 sm:w-14 sm:h-14">
            <svg class="w-6 h-6 sm:w-7 sm:h-7">...</svg>
        </div>
        <p class="text-3xl sm:text-4xl">0</p>
        <p class="text-xs sm:text-sm">Description</p>
    </div>
</div>
```

#### Forms & Inputs
```html
<!-- Login Form -->
<div class="w-full max-w-sm sm:max-w-md">
    <div class="px-6 sm:px-10 pt-8 sm:pt-12">
        <!-- Logo -->
        <div class="w-32 h-32 sm:w-40 sm:h-40 mb-4 sm:mb-6">
            <img src="/assets/images/atlas-logo.png">
        </div>
        
        <!-- Title -->
        <h1 class="text-4xl sm:text-5xl">Atlas</h1>
        
        <!-- Input -->
        <input class="w-full pl-10 sm:pl-12 py-3 sm:py-4 text-sm sm:text-base">
        
        <!-- Button -->
        <button class="w-full py-3 sm:py-4 text-sm sm:text-base">
            SIGN IN
        </button>
    </div>
</div>
```

#### Content Sections
```html
<!-- Info Card with Icon -->
<div class="rounded-xl sm:rounded-2xl p-5 sm:p-6 lg:p-8">
    <div class="flex flex-col sm:flex-row items-start space-y-4 sm:space-y-0 sm:space-x-5">
        <!-- Icon -->
        <div class="w-14 h-14 sm:w-16 sm:h-16">
            <svg class="w-8 h-8">...</svg>
        </div>
        
        <!-- Content -->
        <div class="flex-1">
            <h2 class="text-xl sm:text-2xl mb-2 sm:mb-3">Title</h2>
            <p class="text-sm sm:text-base mb-4 sm:mb-5">Description</p>
        </div>
    </div>
</div>
```

### Responsive Utilities

#### Hide/Show Elements
```html
<!-- Hide on mobile, show on desktop -->
<div class="hidden sm:block">Desktop only</div>

<!-- Show on mobile, hide on desktop -->
<div class="sm:hidden">Mobile only</div>

<!-- Show text on desktop, icon on mobile -->
<button>
    <span class="hidden sm:inline">LOGOUT</span>
    <svg class="sm:hidden">...</svg>
</button>
```

#### Responsive Positioning
```html
<!-- Theme Toggle Button -->
<!-- Fixed on login page -->
<button class="fixed top-4 right-4 sm:top-6 sm:right-6 w-12 h-12 sm:w-14 sm:h-14">

<!-- In header on dashboard -->
<button class="w-10 h-10 sm:w-11 sm:h-11">
```

### Testing Checklist

برای هر صفحه جدید، این سایزها را تست کنید:

- ✅ **Mobile (320px - 640px)**: iPhone SE, iPhone 12/13/14
- ✅ **Tablet (640px - 1024px)**: iPad, Android tablets
- ✅ **Desktop (1024px+)**: Laptops, monitors

### Common Responsive Patterns

```html
<!-- Container -->
<div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">

<!-- Grid Layout -->
<div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4 sm:gap-6">

<!-- Flex Layout -->
<div class="flex flex-col sm:flex-row items-start sm:items-center space-y-4 sm:space-y-0 sm:space-x-4">

<!-- Rounded Corners -->
<div class="rounded-xl sm:rounded-2xl">

<!-- Font Sizes -->
<p class="text-xs sm:text-sm lg:text-base">

<!-- Icon Sizes -->
<svg class="w-5 h-5 sm:w-6 sm:h-6 lg:w-7 lg:h-7">
```

---

## ⚠️ قوانین الزامی

### ✅ همیشه باید:
1. از فونت **Poppins** برای کلمه "Atlas" استفاده شود
2. رنگ‌های Light Mode از پالت **Cyan/Teal** باشد (نه Indigo/Purple)
3. لوگو از مسیر `/assets/images/atlas-logo.png` لود شود
4. Dark Mode بدون تغییر باقی بماند (Cyan-400 با glow)
5. تمام دکمه‌ها gradient از Cyan به Teal داشته باشند
6. Input ها border رنگ Cyan داشته باشند
7. Theme toggle button در گوشه بالا راست باشد
8. Glassmorphism effect در همه کارت‌ها استفاده شود

### ❌ هرگز نباید:
1. از رنگ‌های Indigo/Purple در Light Mode استفاده شود
2. فونت Atlas تغییر کند (باید Poppins باشد)
3. Dark Mode رنگ‌بندی تغییر کند
4. لوگو بدون drop-shadow باشد
5. دکمه‌ها بدون transition باشند

---

## 📄 Template صفحه جدید

```html
<!DOCTYPE html>
<html lang="en" x-data="themeManager()" x-init="initTheme()" :class="{ 'dark': darkMode }">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Atlas VPN Panel - Page Title</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script defer src="https://cdn.jsdelivr.net/npm/alpinejs@3.x.x/dist/cdn.min.js"></script>
    
    <script>
        tailwind.config = {
            darkMode: 'class',
            theme: {
                extend: {
                    fontFamily: {
                        'sans': ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
                        'display': ['Poppins', 'Inter', 'system-ui', 'sans-serif'],
                    },
                    boxShadow: {
                        'glow-cyan': '0 0 20px rgba(34, 211, 238, 0.5), 0 0 40px rgba(34, 211, 238, 0.3)',
                    },
                }
            }
        }
    </script>
    
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&family=Poppins:wght@700;800;900&display=swap" rel="stylesheet">
    
    <style>
        * {
            font-family: 'Inter', system-ui, -apple-system, sans-serif;
        }
        
        .glass-light {
            background: rgba(255, 255, 255, 0.9);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.5);
        }
        
        .glass-dark {
            background: rgba(255, 255, 255, 0.05);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .theme-transition {
            transition: background-color 0.3s ease, color 0.3s ease, border-color 0.3s ease;
        }
    </style>
</head>
<body class="min-h-screen antialiased theme-transition bg-slate-50 dark:bg-slate-950">
    <!-- Theme Toggle -->
    <button 
        @click="toggleTheme()"
        class="fixed top-6 right-6 z-50 w-14 h-14 rounded-2xl theme-transition flex items-center justify-center shadow-xl hover:scale-110 active:scale-95 transition-transform duration-200"
        :class="darkMode ? 'bg-slate-800 text-cyan-400 shadow-glow-cyan' : 'bg-white text-cyan-600 shadow-lg'"
    >
        <svg x-show="!darkMode" class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z"/>
        </svg>
        <svg x-show="darkMode" class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z"/>
        </svg>
    </button>

    <!-- محتوای صفحه -->
    
    <script>
        function themeManager() {
            return {
                darkMode: false,
                
                initTheme() {
                    const savedTheme = localStorage.getItem('atlas-theme');
                    if (savedTheme === 'dark') {
                        this.darkMode = true;
                    } else if (savedTheme === 'light') {
                        this.darkMode = false;
                    } else {
                        this.darkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
                    }
                },
                
                toggleTheme() {
                    this.darkMode = !this.darkMode;
                    localStorage.setItem('atlas-theme', this.darkMode ? 'dark' : 'light');
                }
            }
        }
    </script>
</body>
</html>
```

---

**این استانداردها تا پایان پروژه ثابت و الزامی هستند. هر صفحه یا کامپوننت جدید باید دقیقاً از این قوانین پیروی کند.**
