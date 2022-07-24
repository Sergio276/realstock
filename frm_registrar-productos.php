<?php
require_once './php/session-data.php';
?>
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
          <a href="principal.php" title="Inicio"><i class="fa-solid fa-house-chimney"></i> Inicio </a> / Inventarios /
          Productos
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
          <input type="text" placeholder="Buscar Producto..." />
        </div>
        <button class="btn btn-green" data-btn-modal="true" data-modal="#m-registrar-usuario">Agregar Producto</button>
        <div class="modal-wrapper" id="m-registrar-usuario">
          <div class="modal">
            <div class="modal-header">
              <div>Registrar Producto</div>
              <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
            </div>
            <div class="modal-content">
              <form action="./php/add-product.php" method="post">
                <div class="form-section">
                  <label for="">Subcategoría:</label>
                  <?php
                  include_once './php/config.php';
                  $query_subcat = "SELECT subcategoria_id, nombre FROM tbl_subcategoria";
                  $result_subcat = mysqli_query($conn, $query_subcat);

                  if ($result_subcat) {
                    if (mysqli_num_rows($result_subcat) > 0) {
                  ?>
                      <select required name="subcategory">
                        <option value="">Seleccione la subcategoría</option>
                        <?php
                        foreach ($result_subcat as $row_subcat) {
                        ?>
                          <option value="<?php echo $row_subcat['subcategoria_id'] ?>"><?php echo $row_subcat['nombre'] ?></option>
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
                  <label for="">No de serie:</label>
                  <input required type="number" name="serial" min="1" placeholder="Ingrese el no de serie" />
                </div>
                <div class="form-section">
                  <label for="">Contador inicial:</label>
                  <input required type="text" name="initial_counter" placeholder="Ingrese el contador inicial" />
                </div>
                <div class="form-section">
                  <label for="">Anotación:</label>
                  <input required type="text" name="annotation" placeholder="Ingrese la anotación" />
                </div>
                <div class="form-section">
                  <label for="">Stock máximo:</label>
                  <input required type="number" min="1" name="max_stock" placeholder="Ingrese el stock máximo" />
                </div>
                <div class="form-section">
                  <label for="">Stock mínimo:</label>
                  <input required type="number" min="1" name="min_stock" placeholder="Ingrese el stock mínimo" />
                </div>
                <div class="form-section">
                  <label for="">Estado:</label>
                  <select required name="status">
                    <option value="">Selecione un estado</option>
                    <option value="Rentado">Rentado</option>
                    <option value="Asignado">Asignado</option>
                    <option value="Libre">Libre</option>
                    <option value="Dado de Baja">Dado de Baja</option>
                  </select>
                </div>
                <div class="form-section">
                  <label for="">Marca del fabricante:</label>
                  <input required type="text" name="brand" placeholder="Ingrese la marca del fabricante" />
                </div>
                <div class="form-section">
                  <label for="">Modelo:</label>
                  <input required type="text" name="model" placeholder="Ingrese el modelo" />
                </div>
                <div class="form-section">
                  <label for="">Descripción:</label>
                  <textarea name="description" cols="49" rows="10"></textarea>
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
            <th colspan="15">Productos</th>
          </tr>
          <tr class="titles-table">
            <td class="cell-center">Id</td>
            <td>Categoría</td>
            <td>Subcategoría</td>
            <td>No serie</td>
            <td>Contador inicial</td>
            <td>Anotación</td>
            <td>Stock máximo</td>
            <td>Stock mínimo</td>
            <td>Estado</td>
            <td>Marca</td>
            <td>Modelo</td>
            <td>Descripción</td>
            <td class="cell-center">Editar</td>
          </tr>
          <?php
          $query = "SELECT tbl_categoria.nombre AS catnombre, tbl_subcategoria.nombre AS subcatnombre, tbl_producto.producto_id, tbl_producto.no_serie, tbl_producto.contador_inicial, tbl_producto.anotacion, tbl_producto.stock_maximo, tbl_producto.stock_minimo, tbl_producto.estado, tbl_producto.marca_fabricante, tbl_producto.modelo, tbl_producto.descripcion
          FROM ((tbl_producto
          INNER JOIN tbl_subcategoria
          ON tbl_subcategoria.subcategoria_id = tbl_producto.tbl_subcategoria_id)
          INNER JOIN tbl_categoria
          ON tbl_categoria.categoria_id = tbl_subcategoria.tbl_categoria_id)";

          $result = mysqli_query($conn, $query);

          if ($result) {
            if (mysqli_num_rows($result) > 0) {
              foreach ($result as $row) {
          ?>
                <tr>
                  <td class="cell-center"><?php echo $row['producto_id'] ?></td>
                  <td><?php echo $row['catnombre'] ?></td>
                  <td><?php echo $row['subcatnombre'] ?></td>
                  <td><?php echo $row['no_serie'] ?></td>
                  <td><?php echo $row['contador_inicial'] ?></td>
                  <td><?php echo $row['anotacion'] ?></td>
                  <td><?php echo $row['stock_maximo'] ?></td>
                  <td><?php echo $row['stock_minimo'] ?></td>
                  <td><?php echo $row['estado'] ?></td>
                  <td><?php echo $row['marca_fabricante'] ?></td>
                  <td><?php echo $row['modelo'] ?></td>
                  <td><?php echo $row['descripcion'] ?></td>
                  <td class="cell-center">
                    <div title="Editar" title="Editar" data-btn-modal="true" data-modal="#m-editar-usuario_<?php echo $row['producto_id'] ?>"><img src="img/editar.png" alt="Editar" /></div>
                  </td>
                </tr>

                <div class="modal-wrapper" id="m-editar-usuario_<?php echo $row['producto_id'] ?>">
                  <div class="modal">
                    <div class="modal-header">
                      <div>Editar información de Producto "<?php echo $row['producto_id'] ?>"</div>
                      <i class="fa-solid fa-xmark" data-btn-close="modal"></i>
                    </div>
                    <div class="modal-content">
                      <form action="#">
                        <div class="form-section">
                          <label for="">Categoria:</label>
                          <select>
                            <option value="Impresora">Impresora</option>
                            <option value="Computadores">Computadores</option>
                            <option value="Insumos">Insumos</option>
                          </select>
                        </div>
                        <div class="form-section">
                          <label for="">Subcategoria:</label>
                          <select>
                            <option value="">Seleccione el tipo de movimiento</option>
                            <option value="Multifuncional">Multifuncional</option>
                            <option value="Portatil">Portatil</option>
                            <option value="Toner">Toner</option>
                          </select>
                        </div>
                        <div class="form-section">
                          <label for="">Producto:</label>
                          <input type="text" placeholder="Ingrese un Producto" />
                        </div>
                        <div class="form-section">
                          <label for="">Marca:</label>
                          <input type="text" placeholder="Ingrese una Marca" />
                        </div>
                        <div class="form-section">
                          <label for="">Modelo:</label>
                          <input type="text" placeholder="Ingrese el Modelo" />
                        </div>
                        <div class="form-section">
                          <label for="">No serie:</label>
                          <input type="text" placeholder="Ingrese serial" />
                        </div>
                        <div class="form-section">
                          <label for="">Stock maximo:</label>
                          <input type="number" placeholder="Ingrese un Stock" />
                        </div>
                        <div class="form-section">
                          <label for="">Stock minimo:</label>
                          <input type="number" placeholder="Seleccione un stock min" />
                        </div>
                        <div class="form-section">
                          <label for="">Contador:</label>
                          <input type="number" placeholder="Ingrese Contador maquina" />
                        </div>
                        <div class="form-section">
                          <label for="">Anotacion:</label>
                          <input type="text" placeholder="Ingrese una notacion" />
                        </div>
                        <div class="form-section">
                          <label for="">Estado:</label>
                          <select>
                            <option value="">Selecione un Estado</option>
                            <option value="Rentado">Rentado</option>
                            <option value="Asignado">Asignado</option>
                            <option value="Libre">Libre</option>
                            <option value="Dado de Baja">Dado de Baja</option>
                          </select>
                        </div>
                        <input class="btn btn-green submit" type="submit" value="Actualizar" />
                      </form>
                    </div>
                  </div>
                </div>
          <?php
              }
            }
          }
          ?>
        </table>
      </div>
    </div>
    <footer>Copyright 2022</footer>
  </div>

</body>

</html>