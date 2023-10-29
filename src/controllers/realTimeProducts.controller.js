import { productsService } from "../repository/index.js";
import CustomError from "../services/errors/CustomError.js";
import EErrors from "../services/errors/enum.js";
import {
  generateProductErrorInfo,
  generateAuthErrorInfo,
} from "../services/errors/info.js";

// Metodo asincrono para guardar un producto
async function saveProduct(req, res, next) {
  const { title, description, code, price, stock, category, owner, thumbnail } =
    req.body;

  try {
    if (!title || !description || !price || !code || !stock || !category) {
      const data = { title, description, code, price, stock, category };

      req.logger.error(
        `Error de tipo de dato: Error al crear el producto ${new Date().toLocaleString()}`
      );
      CustomError.createError({
        name: "Error de tipo de datos",
        cause: generateProductErrorInfo(data, EErrors.INVALID_TYPES_ERROR),
        message: "Error al crear el producto",
        code: EErrors.INVALID_TYPES_ERROR,
      });
      res.status(500).json({ message: "Error al crear el producto" });
    }

    const product = {
      title,
      description,
      code,
      price,
      stock,
      owner,
      category,
      thumbnail,
    };

    const result = await productsService.saveOneProduct(product);

    if (!result) {
      req.logger.error(
        `Error de base de datos: Error al crear el producto ${new Date().toLocaleString()}`
      );
      CustomError.createError({
        name: "Error de base de datos",
        cause: generateProductErrorInfo(result, EErrors.DATABASE_ERROR),
        message: "Error al crear el producto",
        code: EErrors.DATABASE_ERROR,
      });
      res.status(500).json({ message: "Error al crear el producto" });
    }

    req.logger.info(`Producto creado con éxito ${new Date().toLocaleString()}`);
    res.json({ message: "Producto creado con éxito", data: product });
  } catch (err) {
    next(err);
  }
}

// Metodo asincrono para eliminar un producto
async function deleteProduct(req, res, next) {
  const { pid } = req.params;
  const userRole = req.user.role;

  try {
    if (!pid) {
      req.logger.error(
        `Error de tipo de dato: Error al eliminar el producto ${new Date().toLocaleString()}`
      );
      CustomError.createError({
        name: "Error de tipo de dato",
        cause: generateProductErrorInfo(pid, EErrors.INVALID_TYPES_ERROR),
        message: "Error al eliminar el producto",
        code: EErrors.INVALID_TYPES_ERROR,
      });
      res.status(500).json({ message: "Error al eliminar el producto" });
    }

    const product = await productsService.getOneProduct(pid);

    if (userRole === "premium" && product.owner !== req.user.user.username) {
      req.logger.error(
        `Error de permisos: Error al eliminar el producto ${new Date().toLocaleString()}`
      );
      CustomError.createError({
        name: "Error de permisos",
        cause: generateAuthErrorInfo(userRole, EErrors.AUTH_ERROR),
        message: "Error al eliminar el producto",
        code: EErrors.AUTH_ERROR,
      });
      res.status(500).json({ message: "Error al eliminar el producto" });
    } else {
      const result = await productsService.deleteOneProduct(pid);
      req.logger.info(
        `Producto eliminado con éxito ${new Date().toLocaleString()}`
      );
      res.json({ message: `Producto eliminado con éxito`, data: result });
    }

    if (!result) {
      req.logger.error(
        `Error de base de datos: Error al eliminar el producto ${new Date().toLocaleString()}`
      );
      CustomError.createError({
        name: "Error de base de datos",
        cause: generateProductErrorInfo(result, EErrors.DATABASE_ERROR),
        message: "Error al eliminar el producto",
        code: EErrors.DATABASE_ERROR,
      });
      res.status(500).json({ message: "Error al eliminar el producto" });
    }

    req.logger.info(
      `Producto eliminado con éxito ${new Date().toLocaleString()}`
    );
    res.json({ message: "Producto eliminado con éxito ", data: result });
  } catch (err) {
    next(err);
  }
}

// Metodo asincrono para actualizar un producto
async function updateProduct(req, res, next) {
  const { pid } = req.params;
  const { title, description, code, price, stock, category, thumbnail } =
    req.body;

  try {
    if (!title || !description || !price || !code || !stock) {
      const data = { title, description, code, price, stock, category };
      req.logger.error(
        `Error de tipo de dato: Error al actualizar el producto ${new Date().toLocaleString()}`
      );
      CustomError.createError({
        name: "Error de tipo de datos",
        cause: generateProductErrorInfo(data, EErrors.INVALID_TYPES_ERROR),
        message: "Error al actualizar el producto",
        code: EErrors.INVALID_TYPES_ERROR,
      });
      res.status(500).json({ message: "Error al actualizar el producto" });
    }

    const product = {
      title,
      description,
      code,
      price,
      stock,
      category,
      thumbnail,
    };

    const result = await productsService.updateOneProduct(pid, product);

    if (!result) {
      req.logger.error(
        `Error de base de datos: Error al actualizar el producto ${new Date().toLocaleString()}`
      );
      CustomError.createError({
        name: "Error de base de datos",
        cause: generateProductErrorInfo(result, EErrors.DATABASE_ERROR),
        message: "Error al actualizar el producto",
        code: EErrors.DATABASE_ERROR,
      });
      res.status(500).json({ message: "Error al actualizar el producto" });
    }
    req.logger.info(
      `Producto actualizado con éxito ${new Date().toLocaleString()}`
    );
    res.json({ message: "Producto actualizado con éxito ", data: product });
  } catch (err) {
    next(err);
  }
}

export { saveProduct, deleteProduct, updateProduct };
