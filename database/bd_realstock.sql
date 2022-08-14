-- phpMyAdmin SQL Dump
-- version 5.0.4
-- https://www.phpmyadmin.net/
--
-- Servidor: 127.0.0.1
-- Tiempo de generación: 28-07-2022 a las 19:01:29
-- Versión del servidor: 10.4.17-MariaDB
-- Versión de PHP: 8.0.0

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";


/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!40101 SET NAMES utf8mb4 */;

--
-- Base de datos: `bd_realstock`
--

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tbl_categoria`
--

CREATE TABLE `tbl_categoria` (
  `categoria_id` int(11) NOT NULL,
  `nombre` varchar(45) DEFAULT NULL,
  `descripcion` tinytext DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tbl_movimiento`
--

CREATE TABLE `tbl_movimiento` (
  `movimiento_id` int(11) NOT NULL,
  `tipo_movimiento` varchar(45) DEFAULT NULL,
  `subtipo_movimiento` varchar(45) DEFAULT NULL,
  `cantidad` int(11) DEFAULT NULL,
  `costo_unitario` varchar(45) DEFAULT NULL,
  `fecha` varchar(45) DEFAULT NULL,
  `descripcion` tinytext DEFAULT NULL,
  `tbl_producto_id` int(11) NOT NULL,
  `tbl_tercero_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tbl_producto`
--

CREATE TABLE `tbl_producto` (
  `producto_id` int(11) NOT NULL,
  `no_serie` int(11) NOT NULL,
  `contador_inicial` varchar(45) DEFAULT NULL,
  `anotacion` varchar(45) DEFAULT NULL,
  `stock_maximo` varchar(45) DEFAULT NULL,
  `stock_minimo` varchar(45) DEFAULT NULL,
  `estado` varchar(45) DEFAULT NULL,
  `marca_fabricante` varchar(45) DEFAULT NULL,
  `modelo` varchar(45) DEFAULT NULL,
  `descripcion` tinytext DEFAULT NULL,
  `tbl_subcategoria_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tbl_rol`
--

CREATE TABLE `tbl_rol` (
  `rol_id` int(11) NOT NULL,
  `nombre` varchar(45) DEFAULT NULL,
  `permisos` longtext CHARACTER SET utf8mb4 COLLATE utf8mb4_bin DEFAULT NULL CHECK (json_valid(`permisos`))
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tbl_subcategoria`
--

CREATE TABLE `tbl_subcategoria` (
  `subcategoria_id` int(11) NOT NULL,
  `nombre` varchar(45) DEFAULT NULL,
  `descripcion` tinytext DEFAULT NULL,
  `tbl_categoria_id` int(11) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tbl_tercero`
--

CREATE TABLE `tbl_tercero` (
  `tercero_id` int(11) NOT NULL,
  `tipo_de_documento` varchar(45) DEFAULT NULL,
  `no_documento` int(11) DEFAULT NULL,
  `razon_social` varchar(45) DEFAULT NULL,
  `estado` varchar(45) DEFAULT NULL,
  `nombre_contacto` varchar(45) DEFAULT NULL,
  `telefono` varchar(45) DEFAULT NULL,
  `pagina_web` varchar(45) DEFAULT NULL,
  `email` varchar(45) DEFAULT NULL,
  `departamento` varchar(45) DEFAULT NULL,
  `ciudad` varchar(45) DEFAULT NULL,
  `direccion` varchar(45) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

-- --------------------------------------------------------

--
-- Estructura de tabla para la tabla `tbl_usuario`
--

CREATE TABLE `tbl_usuario` (
  `usuario_id` int(11) NOT NULL,
  `usuario` varchar(45) DEFAULT NULL,
  `contrasena` varchar(255) DEFAULT NULL,
  `estado` varchar(45) DEFAULT NULL,
  `email` varchar(45) DEFAULT NULL,
  `nombres` varchar(45) DEFAULT NULL,
  `apellidos` varchar(45) DEFAULT NULL,
  `tbl_rol_id` int(11) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8;

--
-- Volcado de datos para la tabla `tbl_usuario`
--

INSERT INTO `tbl_usuario` (`usuario_id`, `usuario`, `contrasena`, `estado`, `email`, `nombres`, `apellidos`, `tbl_rol_id`) VALUES
(1, 'admin', '$2y$12$ZQbnQdxh8p9hCuO6x6L3fuGfU4I9cK2Ikbum.5z7OSNsJmrC3ElUK', 'activo', 'dade@wavcooka.tt', 'Shelton', 'Becker', NULL),
(2, 'user', '$2y$12$/uQmD3IYMSK76zQRiM0tQugr3hhoynDUiOHdXIwiqJNP6D.fsaAAK', 'activo', 'pirmen@odakolu.bw', 'Alan', 'Hammond', NULL);

--
-- Índices para tablas volcadas
--

--
-- Indices de la tabla `tbl_categoria`
--
ALTER TABLE `tbl_categoria`
  ADD PRIMARY KEY (`categoria_id`);

--
-- Indices de la tabla `tbl_movimiento`
--
ALTER TABLE `tbl_movimiento`
  ADD PRIMARY KEY (`movimiento_id`),
  ADD KEY `fk_tbl_movimiento_tbl_producto1_idx` (`tbl_producto_id`),
  ADD KEY `fk_tbl_movimiento_tbl_tercero1_idx` (`tbl_tercero_id`);

--
-- Indices de la tabla `tbl_producto`
--
ALTER TABLE `tbl_producto`
  ADD PRIMARY KEY (`producto_id`),
  ADD KEY `fk_tbl_producto_tbl_subcategoria1_idx` (`tbl_subcategoria_id`);

--
-- Indices de la tabla `tbl_rol`
--
ALTER TABLE `tbl_rol`
  ADD PRIMARY KEY (`rol_id`);

--
-- Indices de la tabla `tbl_subcategoria`
--
ALTER TABLE `tbl_subcategoria`
  ADD PRIMARY KEY (`subcategoria_id`),
  ADD KEY `fk_Tbl_Subcategorias_Tbl_Categorias1_idx` (`tbl_categoria_id`);

--
-- Indices de la tabla `tbl_tercero`
--
ALTER TABLE `tbl_tercero`
  ADD PRIMARY KEY (`tercero_id`);

--
-- Indices de la tabla `tbl_usuario`
--
ALTER TABLE `tbl_usuario`
  ADD PRIMARY KEY (`usuario_id`),
  ADD UNIQUE KEY `usuario_UNIQUE` (`usuario`),
  ADD KEY `fk_tbl_usuario_tbl_rol1_idx` (`tbl_rol_id`);

--
-- AUTO_INCREMENT de las tablas volcadas
--

--
-- AUTO_INCREMENT de la tabla `tbl_categoria`
--
ALTER TABLE `tbl_categoria`
  MODIFY `categoria_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tbl_movimiento`
--
ALTER TABLE `tbl_movimiento`
  MODIFY `movimiento_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tbl_producto`
--
ALTER TABLE `tbl_producto`
  MODIFY `producto_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tbl_rol`
--
ALTER TABLE `tbl_rol`
  MODIFY `rol_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tbl_subcategoria`
--
ALTER TABLE `tbl_subcategoria`
  MODIFY `subcategoria_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tbl_tercero`
--
ALTER TABLE `tbl_tercero`
  MODIFY `tercero_id` int(11) NOT NULL AUTO_INCREMENT;

--
-- AUTO_INCREMENT de la tabla `tbl_usuario`
--
ALTER TABLE `tbl_usuario`
  MODIFY `usuario_id` int(11) NOT NULL AUTO_INCREMENT, AUTO_INCREMENT=3;

--
-- Restricciones para tablas volcadas
--

--
-- Filtros para la tabla `tbl_movimiento`
--
ALTER TABLE `tbl_movimiento`
  ADD CONSTRAINT `fk_tbl_movimiento_tbl_producto1` FOREIGN KEY (`tbl_producto_id`) REFERENCES `tbl_producto` (`producto_id`) ON DELETE NO ACTION ON UPDATE NO ACTION,
  ADD CONSTRAINT `fk_tbl_movimiento_tbl_tercero1` FOREIGN KEY (`tbl_tercero_id`) REFERENCES `tbl_tercero` (`tercero_id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Filtros para la tabla `tbl_producto`
--
ALTER TABLE `tbl_producto`
  ADD CONSTRAINT `fk_tbl_producto_tbl_subcategoria1` FOREIGN KEY (`tbl_subcategoria_id`) REFERENCES `tbl_subcategoria` (`subcategoria_id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Filtros para la tabla `tbl_subcategoria`
--
ALTER TABLE `tbl_subcategoria`
  ADD CONSTRAINT `fk_Tbl_Subcategorias_Tbl_Categorias1` FOREIGN KEY (`tbl_categoria_id`) REFERENCES `tbl_categoria` (`categoria_id`) ON DELETE NO ACTION ON UPDATE NO ACTION;

--
-- Filtros para la tabla `tbl_usuario`
--
ALTER TABLE `tbl_usuario`
  ADD CONSTRAINT `fk_tbl_usuario_tbl_rol1` FOREIGN KEY (`tbl_rol_id`) REFERENCES `tbl_rol` (`rol_id`) ON DELETE NO ACTION ON UPDATE NO ACTION;
COMMIT;

/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
