<?php require_once './php/session-data.php' ?>
<!DOCTYPE html>
<html lang="es">

<head>
  <meta charset="UTF-8" />
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Real Stock</title>
  <link rel="shortcut icon" href="img/favicon.ico" type="image/x-icon">
  <link rel="stylesheet" href="css/estilos.css" />
  <link rel="preconnect" href="https://fonts.googleapis.com" />
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin />
  <link href="https://fonts.googleapis.com/css2?family=Josefin+Sans:wght@300&display=swap" rel="stylesheet" />
  <script defer src="js/script.js"></script>
  <script defer src="https://kit.fontawesome.com/707789a0bc.js" crossorigin="anonymous"></script>
</head>

<body>
  <nav>
    <div class="logo">
      <img src="img/logo.png" alt="" />
    </div>
    <div class="links">
      <ul>
        <li class="link">
          <a href="principal.php">
            <i class="fa-solid fa-house-chimney"></i> Inicio
          </a>
        </li>
        <li class="link">
          <a href="frm_registrar-usuarios.php">
            <i class="fa-solid fa-user-group"></i> Usuarios
          </a>
        </li>
        <li class="link">
          <a href="inventarios.php">
            <i class="fa-solid fa-cart-flatbed"></i> Inventarios
          </a>
        </li>
      </ul>
    </div>
  </nav>
  <div class="wrapper">
    <header>
      <div class="section-header">
        <div class="hamburger-menu">
          <span></span><span></span><span></span>
        </div>
        <div class="location-source">
          <a href="principal.php"><i class="fa-solid fa-house-chimney"></i> Inicio </a> / Inventarios / Subcategorías
        </div>
      </div>
      <div class="section-header">
        <div class="user-tag">
          <a href="frm_editar-perfil.php"><i class="fa-solid fa-circle-user"></i><?php echo $_SESSION['username'] ?></a>
        </div>
        <div class="btn-logout">
          <a href="./php/logout.php"><i class="fa-solid fa-right-from-bracket"></i></a>
        </div>
      </div>
    </header>
    <div class="content">
      <div class="items-container">
        <div class="search-bar">
          <div class="icon-search">
            <i class="fa-solid fa-magnifying-glass"></i>
          </div>
          <input type="text" placeholder="Buscar Subcategoría..." />
        </div>
        <button class="btn btn-green" data-btn-modal="true" data-modal="#m-crear-subcategoria">Registar Subcategoría</button>
        <div class="modal-wrapper" id="m-crear-subcategoria">
          <div class="modal">
            <div class="modal-header">
              <div>Registar Subcategoría</div>
              <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
            </div>
            <div class="modal-content">
              <form action="./php/add-subcategory.php" method="post">
                <div class="form-section">
                  <label for="">Categoría:</label>
                  <?php
                  include_once './php/config.php';
                  $query_cat = "SELECT categoria_id, nombre FROM tbl_categoria";
                  $result_cat = mysqli_query($conn, $query_cat);

                  if ($result_cat) {
                    if (mysqli_num_rows($result_cat) > 0) {
                  ?>
                      <select required name="category">
                        <option value="">Seleccione la categoría</option>
                        <?php
                        foreach ($result_cat as $row_cat) {
                        ?>
                          <option value="<?php echo $row_cat['categoria_id'] ?>"><?php echo $row_cat['nombre'] ?></option>
                        <?php
                        }
                        ?>
                      </select>
                    <?php
                    } else {
                    ?>
                      <input type="text" disabled value="No se encontraron categorías registradas">
                  <?php
                    }
                  } else {
                    echo '<script type="text/javascript">
                    alert("Error al consultar las categorías");
                    </script>';
                  }
                  ?>
                </div>
                <div class="form-section">
                  <label for="">Nombre:</label>
                  <input type="text" name="subcategory" required placeholder="Ingrese el nombre de la subcategoría..." />
                </div>
                <div class="form-section">
                  <label for="">Descripción:</label>
                  <br>
                  <textarea name="description" required rows="8" cols="49"></textarea>
                </div>
                <input class="btn btn-green" type="submit" name="save" value="Guardar" />
              </form>
            </div>
          </div>
        </div>
      </div>
      <div class="wrapper-table">
        <table>
          <tr>
            <th colspan="8">Subcategorías</th>
          </tr>
          <tr class="titles-table">
            <td class="cell-center">Id</td>
            <td>Categoría </td>
            <td>Nombre</td>
            <td>Descripción</td>
            <td class="cell-center">Eliminar</td>
            <td class="cell-center">Editar</td>
          </tr>
          <?php
          $query = "SELECT * FROM tbl_subcategoria";
          $result = mysqli_query($conn, $query);

          if ($result) {
            if (mysqli_num_rows($result) > 0) {
              foreach ($result as $row) {
          ?>
                <tr>
                  <td class="cell-center"><?php echo $row['subcategoria_id'] ?></td>
                  <td><?php echo $row['tbl_categoria_id'] ?></td>
                  <td><?php echo $row['nombre'] ?></td>
                  <td><?php echo $row['descripcion'] ?></td>
                  <td class="cell-center">
                    <div data-btn-modal="true" data-modal="#m-eliminar-rol_<?php echo $row['subcategoria_id'] ?>"><img src="img/delete.png" alt="" /></div>
                  </td>
                  <td class="cell-center">
                    <div title="Editar" data-btn-modal="true" data-modal="#m-editar-rol_<?php echo $row['subcategoria_id'] ?>"><img src="img/editar.png" alt="Editar" /></div>
                  </td>
                </tr>

                <div class="modal-wrapper" id="m-eliminar-rol_<?php echo $row['subcategoria_id'] ?>">
                  <div class="modal">
                    <div class="modal-header">
                      <div>Eliminar categoria</div>
                      <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                    </div>
                    <div class="modal-content">
                      <h2>¿Está seguro de eliminar “<?php echo $row['nombre'] ?>"?</h2>
                      <div class="options-delete">
                        <a href="./php/delete-subcategory.php?php echo $row['subcategoria_id'] ?>" class="btn btn-red">Eliminar</a>
                        <button class="btn btn-gray" data-btn-cancel="modal">Cancelar</button>
                      </div>
                    </div>
                  </div>
                </div>
                <div class="modal-wrapper" id="m-editar-rol_<?php echo $row['subcategoria_id'] ?>">
                  <div class="modal">
                    <div class="modal-header">
                      <div>Editar categoria</div>
                      <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                    </div>
                    <div class="modal-content">
                      <form action="#">
                        <div class="form-section">
                          <label for="">Categoria:</label>
                          <input type="text" placeholder="Ingrese el nombre de la categoria..." />
                        </div>
                        <div class="form-section">
                          <label for="">Nombre:</label>
                          <input type="text" placeholder="Ingrese el nombre de la categoria..." />
                        </div>
                        <div class="form-section">
                          <label for="">Descripción:</label>
                          <br>
                          <textarea name="descripcion" rows="8" cols="49"></textarea>
                        </div>
                        </label>
                        <input class="btn btn-green submit" type="submit" value="Actualizar" />
                      </form>
                    </div>
                  </div>
                </div>
          <?php
              }
            } else {
              echo '<script type="text/javascript">
              alert("No se encontraron subcategorías registradas");
              </script>';
            }
          } else {
            echo '<script type="text/javascript">
            alert("Error al consultar las subcategorías");
            </script>';
          }
          ?>
        </table>
      </div>
    </div>
    <footer>Copyright 2022</footer>
  </div>

</body>

</html