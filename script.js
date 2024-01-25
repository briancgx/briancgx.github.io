// JavaScript para manejar la navegación o cualquier otra interactividad
document.addEventListener("DOMContentLoaded", () => {
    // Tu código aquí
});

document.addEventListener("DOMContentLoaded", function() {
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            document.querySelector('.navbar').classList.add('smaller');
        } else {
            document.querySelector('.navbar').classList.remove('smaller');
        }
    });
});

document.addEventListener('DOMContentLoaded', function () {
    var mobileMenu = document.getElementById('mobile-menu');
    var navLinks = document.querySelector('.nav-links');

    mobileMenu.addEventListener('click', function () {
        navLinks.classList.toggle('active');
    });
});


  /* JavaScript para cambiar los slides suavemente */
document.addEventListener('DOMContentLoaded', () => {
    let slides = document.querySelectorAll('.sponsors-slide');
    let currentSlide = 0;

    setInterval(() => {
        slides[currentSlide].classList.remove('active');
        currentSlide = (currentSlide + 1) % slides.length;
        slides[currentSlide].classList.add('active');
    }, 3000); // Cambia cada 3 segundos
});


document.addEventListener('DOMContentLoaded', function() {
    // Oculta todos los testimonios excepto el primero
    const items = document.querySelectorAll('.testimonial-item');
    items.forEach(function(item, index) {
      if (index > 0) item.classList.add('hidden'); // Añadir clase 'hidden' a todos excepto al primero
    });
  
    let currentIndex = 0;
    const totalItems = items.length;
  
    function cycleItems() {
      const currentItem = document.querySelector('.testimonial-item.active');
      currentItem.classList.remove('active');
      currentItem.classList.add('hidden'); // Añadir clase 'hidden' para ocultar
  
      currentIndex = (currentIndex + 1) % totalItems;
      const nextItem = items[currentIndex];
      nextItem.classList.add('active');
      nextItem.classList.remove('hidden'); // Eliminar clase 'hidden' para mostrar
    }
  
    setInterval(cycleItems, 2500);
  });
  
