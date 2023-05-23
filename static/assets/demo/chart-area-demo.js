// chart.js

// Include the Chart.js library and the chartjs-plugin-datalabels plugin in your HTML file before using this code.

function createPieChart(data) {
  var labels = data.map(function(row) {
    return row['Club Name'];
  });

  var counts = data.map(function(row) {
    return row['Count'];
  });

  var options = {
    tooltips: {
    enabled: true,
    callbacks: {
    label: function(tooltipItem, data) {
    var dataset = data.datasets[tooltipItem.datasetIndex];
    var total = dataset.data.reduce(function(previousValue, currentValue, currentIndex, array) {
    return previousValue + currentValue;
    });
    var currentValue = dataset.data[tooltipItem.index];
    var percentage = ((currentValue / total) * 100).toFixed(1);
    return data.labels[tooltipItem.index] + ': ' + currentValue + ' (' + percentage + '%)';
    }
    }
    },
    datalabels: {
    enabled: true,
    formatter: function(value, data) {
    return value + '%';
    },
    anchor: 'end',
    align: 'center',
    offset: 3
    }
    };
  
  var ctx = document.getElementById('piechart').getContext('2d');
  var chart = new Chart(ctx, {
    type: 'pie',
    data: {
      labels: labels,
      datasets: [{
        data: counts,
        backgroundColor: [
          'rgba(255, 99, 132, 0.7)',
          'rgba(54, 162, 235, 0.7)',
          'rgba(255, 206, 86, 0.7)',
          'rgba(75, 192, 192, 0.7)',
          'rgba(153, 102, 255, 0.7)',
          'rgba(255, 159, 64, 0.7)'
        ]
      }]
    },
    options: options
  });
}
