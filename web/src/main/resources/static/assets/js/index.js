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
  return new Promise((resolve, reject) => {
    $("#columns").empty()
    var file = $("#dataset-input")[0].files[0];
    if(file) {
      var reader = new FileReader();
      reader.onload = function(event) {
        var allText = event.target.result;
        var allTextLines = allText.split(/\r\n|\n/);
        var entries = allTextLines[0].split(',')

        $.each(entries, function (i, entry) {
          var id = entry + "-column-select"
          var col = $("<div></div>").addClass("col mb-3 d-grid");
          var checkboxButton = $("<input>").attr({type: "checkbox", id: id, value: entry, name: "column"})
          .addClass("btn-check checked-focus")
          var label = $("<label></label>").addClass("btn btn-primary p-2 align-self-center").attr("for", id).text(entry)

          col.append(checkboxButton)
          col.append(label)
          $('#columns').append(col)
        })
        console.log('done')
        resolve('DONE')
      };

      reader.onerror = function(event) {
        console.log("parse error")
        $('#dataset-input').val('')
        $('#details').empty()
        reject('ERROR')
      };

      reader.readAsText(file)
    }
  })
}

function createAlgorithmSelector(column) {
  var id = column + "-algorithm-choice"

  var div = $('<div></div>').addClass('form-floating mb-3')
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
  var div = $('<div></div>').addClass('form-floating mb-3')
  var input = $('<input>').addClass('form-control').attr({type: 'text', id: id, 'required': mode == "decrypt"})
  var label = $('<label></label>').attr('for', id).text('Base64 Encoded Key')
  div.append(input)
  div.append(label)

  return div
}

function createKeySizeSelector(column) {
  var id = column + "-key-size"

  var div = $('<div></div>').addClass('form-floating mb-3')
  var selector = $("<select></select>").addClass("form-select").attr({ id: id, 'aria-label': column + " key size select"})
  var label  = $('<label></label>').attr("for", id).text("Choose the key size")

  div.append(selector)
  div.append(label)

  return div
}

function createTaxonomyInput(column) {

  var id = column + "-taxonomy"

  var div = $('<div></div>').addClass('mb-3')
  var input = $('<input>').addClass('form-control').attr({type: "file", id: id +'-file'})
  var label = $('<label></label>').addClass('form-label mt-2').attr("for", id +'-file').text('Upload a taxonomy tree (in JSON)')

  var p = $('<p></p>').addClass('mt-3 mb-2').text('...and edit it if you need to')
  var blackboard = $('<pre></pre>').addClass('overflow-auto mb-3 rounded-2').attr('id', id).css('height', '300px')

  div.append(label)
  div.append(input)
  div.append(p)
  div.append(blackboard)

  $(input).on('change' , function(){
    var file = this.files[0];
    if(file) {
      var reader = new FileReader();
      reader.onload = function(event) {
        var json = event.target.result;
        var result = JSON.parse(json)

        var editor = new JsonEditor('#' + id, algorithmsDetails)
        editor.load(result)

        $(this).val('')
      }
    }
    reader.readAsText(file)
  });

  return div
}

function createParamInput(column, family, param, mode) {
  var id = column + "-param-" + param.field

  if(family == 'OPE' && mode == 'decrypt') return

  var div = $('<div></div>').addClass('form-floating').attr({'data-bs-toggle': "tooltip", 'data-bs-placement': "top", title: param.description})
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
    div = $("<div></div>").addClass("col d-grid");
    input = $("<input>").attr({type: "checkbox", id: id, value: param.field}).addClass("btn-check checked-focus")
    label.addClass("btn btn-primary p-3")
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
    if(algorithm.parameters != null && algorithm.parameters.length != 0)
    parametersRow.append($('<div class="col-12"><p class="mb-0">Algorithm specific parameters: </p></div>'))

    $.each(algorithm.parameters, function (i, param) {
      var col = $('<div></div>').addClass('col col-sm-12')
      col.append(createParamInput(column, algorithm.family, param, mode))
      parametersRow.append(col)
    })
    initTooltips()
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

  var previousColumns = [];
  var previousDataset = "";
  var previousMode = "";
  var uploadedConfig = {};

  $("#wizard").steps({
    headerTag: "h3",
    bodyTag: "section",
    titleTemplate: "#title#",
    transitionEffect: "slide",
    autoFocus: true,
    onStepChanging: function (event, currentIndex, newIndex) {
      if(newIndex == 1) {
        var dataset = $('#dataset-input').val()

        if($('#output-filename').val().length == 0) return false
        if(dataset == null || dataset == "") return false

        if(previousDataset != dataset) {
          previousDataset = dataset
          var promise = extractColumns();
          if(!uploadedConfig.columns_init) {

            promise.then( (msg) => {
              $.each(uploadedConfig.encryption_details, function(i, detail) {
                var id = detail.column_name + "-column-select"
                var checkbox = $('#' + id)
                if(checkbox != null) checkbox.prop('checked', true);
              })
            }
          )
          uploadedConfig.columns_init = true
        }

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

      if(!uploadedConfig.algorithms_init) {
        $.each(uploadedConfig.encryption_details, function(i, detail) {
          var column = detail.column_name

          $('#' + column + "-algorithm-choice").val(detail.cipher).change()

          if(detail.key != null) $('#' + column + "-key").val(detail.key)

          var keySizeInput = $('#' + column + "-key-size")
          if(detail.key_size != null && keySizeInput != null) keySizeInput.val(detail.key_size)

          if(detail.taxonomy_tree != null) jsonEditors[column].load(detail.taxonomy_tree.tree)

          for (var param in detail.params) {
            var paramInput = $('#' + column + '-param-' + param)
            if(paramInput != null) {
              if(paramInput.is(':checkbox')) paramInput.prop('checked', detail.params[param])
              else paramInput.val(detail.params[param])
            }
          }
        })
      }

      uploadedConfig.algorithms_init = true
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

$('#config-input').on('change' , function() {
  var file = this.files[0];
  if(file) {
    var reader = new FileReader();
    reader.onload = function(event) {
      var json = event.target.result;
      uploadedConfig = JSON.parse(json)
      $(this).val('')

      $('#output-filename').val(uploadedConfig.output_filename)
      $("input[name=mode-radio][value=" + uploadedConfig.mode + "-mode]").prop('checked', true);

      console.log(uploadedConfig)
    }
  }
  reader.readAsText(file)
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
      if(input != null && input.val() != '') {
        if(input.is(':checkbox')) params[param.field] = input.is(':checked')
        else if(input.attr('type') == 'number') params[param.field] = parseInt(input.val())
        else params[param.field] = input.val()
      }
    })

    detail.params = params
    config.encryption_details[i] = detail
  })

  return config
}
