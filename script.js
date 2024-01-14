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
