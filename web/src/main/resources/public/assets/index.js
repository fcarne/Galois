var algorithmsDetails = []

function fetchAlgorithms() {
  fetch('/details').then(function(response) { return response.json();})
  .then(function(data) {
    $.each( data, function(key, val) {
      algorithmsDetails.push(val);
    });

    console.log(algorithmsDetails)
  }).catch(function(err) {
    console.log('Fetch problem: ' + err.message);
  });
}

function extractColumns(){
  $("#columns").empty()
  var file = document.getElementById("dataset-input").files[0];
  if(file) {
    var reader = new FileReader();
    reader.onload = function(event) {
      var allText = event.target.result;
      var allTextLines = allText.split(/\r\n|\n/);
      var entries = allTextLines[0].split(',')

      $.each(entries, function (i, entry) {
        var id = "btn-check-" + entry
        var col = $("<div></div>").addClass("col d-flex justify-content-center");
        var checkboxButton = $("<input>").attr({type: "checkbox", id: id, value: entry, name: "column"})
        .addClass("btn-check")
        var label = $("<label></label>").addClass("btn btn-outline-primary w-75 p-1").attr("for", id).text(entry)

        col.append(checkboxButton)
        col.append(label)
        $('#columns').append(col)
      })
    }
    reader.readAsText(file)
    return true
  } else return false
}

function arraysEqual(a, b) {
  if (a === b) return true;
  if (a == null || b == null) return false;
  if (a.length !== b.length) return false;

  for (var i = 0; i < a.length; ++i) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

function createAlgorithmSelector(column) {
  var id = column + "-algorithm-choice"
  var group = $('<div></div>').addClass('input-group mb-3')
  var label  = $('<label></label>').addClass('input-group-text')
  .attr("for", id).text("Algorithm for " + column)
  var selector = $("<select></select>").addClass("form-select").attr("id", id)

  $.each(algorithmsDetails, function (i, algorithm) {
    $(selector).append($('<option>', {
      value: algorithm.name,
      text : algorithm.name
    }));
  })

  // da rivedere

  group.append(label)
  group.append(selector)

  return group
}


$(window).on('load', function() {
  fetchAlgorithms()

  var previousColumns = []
  var previousDataset = ""
  $("#wizard").steps({
    headerTag: "h3",
    bodyTag: "section",
    transitionEffect: "slideLeft",
    autoFocus: true,
    onStepChanging: function (event, currentIndex, newIndex) {
      if(newIndex == 1) {
        var dataset = $('#input-dataset').val()
        if($('#output-filename').val().length == 0) return false
        if(previousDataset != dataset) {
          previousDataset = dataset
          return extractColumns()
        } else return true

      }

      if(newIndex == 2) {
        var columnsSelected = []
        $.each($("#columns input[name='column']:checked"), function(){
          columnsSelected.push($(this).val());
        });
        if(!arraysEqual(columnsSelected, previousColumns)) {
          previousColumns = columnsSelected
          var container = $("#algorithm-choice-container")
          container.empty()

          $.each(columnsSelected, function(i, column) {
            var algorithmSelector = createAlgorithmSelector(column)
            container.append(algorithmSelector)
          })
        }

      }

      if(newIndex < currentIndex) return true

      return true
    }
  });
});
