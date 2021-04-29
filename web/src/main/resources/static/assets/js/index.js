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
    };

    reader.onerror = function(event) {
      console.log("parse error")
      $('#dataset-input').val('')
      $('#details').empty()
    };

    reader.readAsText(file)
  }
}

function createAlgorithmSelector(column) {
  var id = column + "-algorithm-choice"

  var div = $('<div></div>').addClass('form-floating')
  var selector = $("<select></select>").addClass("form-select").attr({ id: id, 'aria-label': column + " algorithm select"})
  var label  = $('<label></label>').attr("for", id).text("Choose the algorithm")

  $.each(algorithmsDetails, function (i, algorithm) {
    $(selector).append($('<option>', {
      value: algorithm.name,
      text : algorithm.name
    }));
  })
  div.append(selector)
  div.append(label)

  return div
}

function createKeyInput(column, mode) {
  var id = column + "-key"
  var keyDiv = $('<div></div>').addClass('form-floating mb-3')
  var keyInput = $('<input>').addClass('form-control').attr({type: 'text', id: id, 'required': mode == "decrypt"})
  var keyLabel = $('<label></label>').attr('for', id).text('Base64 Encoded Key')
  keyDiv.append(keyInput)
  keyDiv.append(keyLabel)

  return keyDiv
}

function createKeySizeSelector(column) {
  var id = column + "-key-size"

  var div = $('<div></div>').addClass('form-floating')
  var selector = $("<select></select>").addClass("form-select").attr({ id: id, 'aria-label': column + " key size select"})
  var label  = $('<label></label>').attr("for", id).text("Choose the key size")

  div.append(selector)
  div.append(label)

  return div
}

function createTaxonomyInput(column) {

  var id = column + "-taxonomy"

  var div = $('<div></div>').addClass('mb-3')
  var jsonInput = $('<input>').addClass('form-control').attr({type: "file", id: id +'-file'})
  var jsonInputLabel = $('<label></label>').addClass('form-label').attr("for", id +'-file').text('Upload a json file')

  var jsonDiv = $('<pre></pre>').addClass('overflow-auto').attr('id', id).css('height', '300px')

  div.append(jsonInputLabel)
  div.append(jsonInput)
  div.append(jsonDiv)

  $(jsonInput).on('change' , function(){
    var file = document.getElementById(jsonInput.attr('id')).files[0];
    if(file) {
      var reader = new FileReader();
      reader.onload = function(event) {
        var allText = event.target.result;
        var result = JSON.parse(allText)

        var editor = new JsonEditor('#'+id, algorithmsDetails)
        editor.load(result)

        $(jsonInput).val('')
      }
    }
    reader.readAsText(file)
  });

  return div
}

function createParamInput(column, family, param, mode) {
  var id = column + "-param-" + param.field

  if(family == 'OPE' && mode == 'decrypt') return

  var div = $('<div></div>').addClass('form-floating mb-3').attr({'data-bs-toggle': "tooltip", 'data-bs-placement': "top", title: param.description})
  var label = $('<label></label>').attr("for", id).text(param.field)

  var input
  switch(param.condition_type) {
    case "REGEX":
    input = $('<input>').addClass('form-control').attr({type: 'text', id: id, pattern: param.condition})
    break;
    case "RANGE":
    var range = param.condition.split('..')
    input = $('<input>').addClass('form-control').attr({type: 'number', id: id, min: range[0], max: range[1]})
    break;
    case "LOWER_LIMIT":
    input = $('<input>').addClass('form-control').attr({type: 'number', id: id, min: param.condition})
    break;
    case "DISTINCT_VALUES":
    var values = param.condition.split(', ')
    input = $("<select></select>").addClass("form-select").attr({ id: id, 'aria-label': param.description})
    input.append($('<option>').text('-- select an option --'))
    $.each(values, function (i, val) {
      input.append($('<option>', {
        value: val,
        text : val
      }));
    })
    break;
    case "BOOLEAN":
    div = $("<div></div>").addClass("col d-flex justify-content-center");
    input = $("<input>").attr({type: "checkbox", id: id}).addClass("btn-check")
    label.addClass("btn btn-outline-primary w-75 p-1")
    break;
  }

  div.append(input)
  div.append(label)
  return div
}

function createDetailsAccordion(column, mode) {
  var id = column + "-accordion"

  var div = $('<div></div>').addClass('accordion-item').attr("id", id)
  var title = $('<h2></h2>').addClass('accordion-header').attr('id', id +"-header")
  var controls = $('<button></button>').addClass('accordion-button collapsed')
  .attr({type: "button", 'data-bs-toggle': "collapse", 'data-bs-target': '#'+id+'-item',
  'aria-expanded': "false", 'aria-controls': id+'-item'}).text('Set the parameters for ' + column)
  title.append(controls)

  var item = $('<div></div>').addClass('accordion-collapse collapse').attr({id: id+'-item', 'aria-labelledby': id+'-header', 'data-bs-parent': '#details'})
  var itemBody = $('<div></div>').addClass('accordion-body')

  var algorithmSelector = createAlgorithmSelector(column)
  itemBody.append(algorithmSelector)

  itemBody.append(createKeyInput(column, mode))

  if(mode == 'encrypt') {
    var keySizeSelector = createKeySizeSelector(column)
    itemBody.append(keySizeSelector)

    algorithmSelector.children('select').on('change', function() {
      var keySizes = algorithmsDetails.find(x => this.value == x.name).key_sizes;
      $(keySizeSelector).children('select').empty()
      $.each(keySizes, function (i, size) {
        $(keySizeSelector).children('select').append($('<option>', {
          value: size,
          text : size
        }));
      })
    })
  }
  itemBody.append(createTaxonomyInput(column))

  var parametersRow = $('<div></div>').addClass('row g-3')
  itemBody.append(parametersRow)

  algorithmSelector.children('select').on('change', function() {
    var algorithm = algorithmsDetails.find(x => this.value == x.name)
    parametersRow.empty()
    $.each(algorithm.parameters, function (i, param) {
      var col = $('<div></div>').addClass('col col-sm-12')
      col.append(createParamInput(column, algorithm.family, param, mode))
      parametersRow.append(col)
    })
    //initTooltips()
  })

  algorithmSelector.children('select').change();

  item.append(itemBody)
  div.append(title)
  div.append(item)
  return div
}

var jsonEditors = {}
var config = {}

$(window).on('load', function() {
  fetchAlgorithms()

  var previousColumns = []
  var previousDataset = ""
  var previousMode
  $("#wizard").steps({
    headerTag: "h3",
    bodyTag: "section",
    transitionEffect: "slideLeft",
    autoFocus: true,
    onStepChanging: function (event, currentIndex, newIndex) {
      if(newIndex == 1) {
        var dataset = $('#dataset-input').val()

        if($('#output-filename').val().length == 0) return false
        if(previousDataset != dataset) {
          previousDataset = dataset
          extractColumns()
        }

      }

      if(newIndex == 2) {
        var columnsSelected = []
        $.each($("#columns input[name='column']:checked"), function(){
          columnsSelected.push($(this).val());
        });

        if(columnsSelected.length === 0) return false

        var toRemove = previousColumns.filter(x => !columnsSelected.includes(x));
        $.each(toRemove, function(i, column) {
          $('#' + column + "-accordion").remove()
          delete jsonEditors[column]
        })

        var container = $("#details")
        var toAdd = columnsSelected.filter(x => !previousColumns.includes(x));

        var mode = $('input[name=mode-radio]:checked').val()
        if(previousMode != mode) {
          toAdd = columnsSelected
          container.empty()
          previousMode = mode // triggers rebuilding of accordion inputs
        }

        $.each(toAdd, function(i, column) {
          var accordionItem = createDetailsAccordion(column, mode)
          container.append(accordionItem)

          jsonEditors[column] = new JsonEditor('#'+column+'-taxonomy') // must be done when the json container is added to the dom
        })

        previousColumns = columnsSelected
      }

      if(newIndex == 3) {
        config = getConfig(previousMode, previousColumns)
        var summaryEditor = new JsonEditor('#summary', config)
      }

      if(newIndex < currentIndex) return true

      return true
    },
    onFinishing: function (event, currentIndex) {
      if(!$('#confirm-switch').is(':checked')) return false

      var formData = new FormData();
      formData.append("dataset", document.getElementById("dataset-input").files[0]);
      formData.append("config", JSON.stringify(config));

      $.ajax({
        url: '/doFinal',
        type: 'post',
        data: formData,
        contentType: false,
        processData: false,
                xhrFields: {
                            responseType: 'blob'
                        },
        success: function (data) {
          console.log(data)
          var a = document.createElement('a');
          var url = window.URL.createObjectURL(data);
          a.href = url;
          a.download = config.output_filename + '-' + Date.now() + '.zip';
          document.body.append(a);
          a.click();
          a.remove();
          window.URL.revokeObjectURL(url);
        },
        error: function(XMLHttpRequest, textStatus, errorThrown) {
          alert("Status: " + textStatus+ "Error: " + errorThrown);
        }
      });

      return true
    }
  });
});

function initTooltips() {
  var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
  var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
    return new bootstrap.Tooltip(tooltipTriggerEl)
  })
}

function getConfig(mode, columns) {
  var config = {
    output_filename: $('#output-filename').val(),
    mode: mode,
    encryption_details: []
  }
  $.each(columns, function(i, column) {
    var algorithm = $('#' + column + '-algorithm-choice').val()
    var detail = {
      column_name: column,
      cipher: algorithm,
    }

    var key = $('#' + column + '-key').val()
    if(key != null && key != '') detail.key = key

    var params = {}

    try {
      var tree = jsonEditors[column].get()
      if(!$.isEmptyObject(tree)) {
        params.taxonomy_tree = {}
        params.taxonomy_tree.tree = tree
      }
    } catch (ex) {
      console.log('empty tree')
    }

    var keySize = $('#' + column + '-key-size')
    if(keySize != undefined && keySize != null) params.key_size = keySize.val()

    var parameters =  algorithmsDetails.find(x => algorithm == x.name).parameters
    $.each(parameters, function(i, param) {
      var input = $('#' + column + "-param-" + param.field)
      if(input != undefined && input != null) {
        if(input.is(':checkbox')) params[param.field] = input.is(':checked')
        else params[param.field] = input.val()
      }
    })

    detail.params = params
    config.encryption_details[i] = detail
  })

  return config
}
