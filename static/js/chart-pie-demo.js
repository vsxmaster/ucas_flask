// Set new default font family and font color to mimic Bootstrap's default styling
Chart.defaults.global.defaultFontFamily = '-apple-system,system-ui,BlinkMacSystemFont,"Segoe UI",Roboto,"Helvetica Neue",Arial,sans-serif';
Chart.defaults.global.defaultFontColor = '#292b2c';

// Retrieve the data from Flask and parse it
var clubFilenames = JSON.parse('{{ club_filenames|safe }}');
var clubCounts = JSON.parse('{{ club_counts|safe }}');
var labels = Object.keys(clubCounts);
var values = Object.values(clubCounts);

// Pie Chart Example
var ctx = document.getElementById('pieChart');
var pieChart = new Chart(ctx, {
    type: 'pie',
    data: {
        labels: labels,
        datasets: [{
            data: values,
            backgroundColor: ['red', 'blue', 'green', 'yellow'],  // Add colors as needed
        }]
    },
    options: {
        responsive: true,
        title: {
            display: true,
            text: 'File Count by Club'
        },
        
    }
});



