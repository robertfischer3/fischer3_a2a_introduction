// Custom JavaScript for A2A Protocol documentation

// Add copy button functionality enhancement
document.addEventListener('DOMContentLoaded', function() {
  // Add version selector if needed
  // Add search analytics if needed
  // Add custom interactions
  
  console.log('A2A Protocol Documentation loaded');
});

// Smooth scrolling for anchor links
document.querySelectorAll('a[href^="#"]').forEach(anchor => {
  anchor.addEventListener('click', function (e) {
    e.preventDefault();
    const target = document.querySelector(this.getAttribute('href'));
    if (target) {
      target.scrollIntoView({
        behavior: 'smooth',
        block: 'start'
      });
    }
  });
});