document.addEventListener("DOMContentLoaded", function() {
    // Controlador de clics para la navegación principal
    document.querySelectorAll('nav a').forEach(link => {
        link.addEventListener('click', function(e) {
            // Comprueba si el enlace es parte del blog y debe ser ignorado
            if (!link.closest('#blog')) {
                e.preventDefault(); // Evita la recarga de la página

                fetch(link.getAttribute('href'))
                    .then(response => {
                        if (response.ok) {
                            return response.text();
                        } else {
                            throw new Error('No se pudo cargar la página');
                        }
                    })
                    .then(data => {
                        document.getElementById('main-content').innerHTML = data;
                        history.pushState(null, '', link.href);
                    })
                    .catch(error => {
                        console.error('Error al cargar la página:', error);
                    });
            }
        });
    });

    // Lógica para el formulario de presupuesto
    const form = document.querySelector('#presupuesto form');
    if (form) {
        form.addEventListener('submit', function(e) {
            e.preventDefault(); // Evita la recarga de la página al enviar el formulario

            const minPrice = document.getElementById('min-price').value;
            const maxPrice = document.getElementById('max-price').value;

            console.log(`Rango de precios seleccionado: ${minPrice} - ${maxPrice}`);

            // Simula la carga de resultados de productos filtrados
            fetch('resultados-presupuesto.html?min-price=' + minPrice + '&max-price=' + maxPrice)
                .then(response => response.text())
                .then(data => {
                    document.getElementById('main-content').innerHTML = data;
                })
                .catch(error => {
                    console.error('Error al cargar los productos:', error);
                });
        });
    }
});
