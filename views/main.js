let todoList = [];
// waits for the DOM to load before trying to run code
$(document).ready(() => {
  $.getJSON('/api/todos')
  .then(addTodos)

  // Create todo on enter
  $('#todoInput').keypress((event) => {
    if(event.which === 13) {
        createTodo();
    }
  });
  // add listener to the list, but looking for clicks on spans inside of that list
  $('.list').on('click', 'span', function(event) {
    event.stopPropagation();
    removeTodo($(this).parent());
  });

  $('.list').on('click', 'li', function() {
    updateTodo($(this));
  });
});

function addTodos(todos) {
  // add todos to the page
  todos.forEach((todo) => {
    addTodo(todo);
  });
}

// Add todo to the page
function addTodo(todo) {
  const newTodo = $(`<li class="task">${todo.name}<span>X</span></li>`);
  newTodo.data('id', todo.id);
  newTodo.data('completed', todo.completed);
  if(todo.completed) {
    newTodo.addClass('done');
  }
  $('.list').append(newTodo);
}

function createTodo() {
  // send request to create new todo
  const userInput = $('#todoInput').val();
  // Send post request, and add response to the page
  $.post('/api/todos', {name: userInput})
  .then((newTodo) => {
    $('#todoInput').val('');
    addTodo(newTodo);
  })
  .catch((err) => {
    console.log(err);
  });
}

// Sends delete request to /api/todos/:id
// Then removes the todo from the page
function removeTodo(todo) {
  const id = todo.data('id');
  $.ajax({
    method: 'DELETE',
    url: '/api/todos/' + id
  })
  .then((data) => {
    todo.remove();
  })
  .catch((err) => {
    console.log(err);
  });
}

// Changes values of todo, in this case
// only affects the completed status
function updateTodo(todo) {
  const id = todo.data('id');
  const isDone = !todo.data('completed') ? 1 : 0;
  const updateData = {completed: isDone};
  $.ajax({
    method: 'PUT',
    url: '/api/todos/' + id,
    data: updateData
  })
  .then((updatedTodo) => {
    todo.toggleClass('done');
    todo.data('completed', isDone);
  })
  .catch((err) => {
    console.log(err);
  })
}
