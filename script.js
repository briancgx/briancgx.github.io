// JavaScript para manejar la navegación o cualquier otra interactividad

document.addEventListener("DOMContentLoaded", function() {
    window.addEventListener('scroll', function() {
        if (window.scrollY > 50) {
            document.querySelector('.navbar').classList.add('smaller');
        } else {
            document.querySelector('.navbar').classList.remove('smaller');
        }
    });
});


/* JavaScript para el botón de menú de hamburguesa */
document.addEventListener('DOMContentLoaded', () => {
    const navbarToggle = document.querySelector('.navbar-toggle');
    const navLinks = document.querySelector('.nav-links');

    // Función para alternar la visibilidad del menú de navegación
    navbarToggle.addEventListener('click', () => {
        navLinks.classList.toggle('active');
    });

    // Añadir un evento a cada enlace para cerrar el menú cuando se hace clic
    document.querySelectorAll('.nav-links a').forEach(link => {
        link.addEventListener('click', () => {
            if(navLinks.classList.contains('active')) {
                navLinks.classList.remove('active');
            }
        });
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
  
