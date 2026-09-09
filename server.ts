import express, { Request, Response } from 'express';
import path from 'path';
import { createServer as createViteServer } from 'vite';
import {
  getDb,
  saveDb,
  hashPasswordServer,
  verifyPasswordServer,
  checkServerLockout,
  recordFailedServerAttempt,
  resetServerLockout,
  createServerSession,
  validateServerSession,
  invalidateServerSession,
  invalidateAllUserSessions,
} from './server/db';
import { User, Product, Category, Order, PurchaseInvoice, DiscountCoupon, Review, Banner, StoreSettings } from './src/types';

// Helper to remove passwordHash from user object before sending to client
function sanitizeUser(user: User): Omit<User, 'passwordHash'> {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { passwordHash, ...safe } = user;
  return safe;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Body parsers with large limits for high-res logo upload & backups
  app.use(express.json({ limit: '50mb' }));
  app.use(express.urlencoded({ extended: true, limit: '50mb' }));

  // Initialize server database on boot
  const db = getDb();
  console.log(`[Zeina Server] Database loaded with ${db.products.length} products, ${db.orders.length} orders, ${db.users.length} users.`);

  // -------------------------------------------------------------
  // API Routes
  // -------------------------------------------------------------

  // Health check
  app.get('/api/health', (_req: Request, res: Response) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // Complete data bundle for frontend hydration
  app.get('/api/data', (_req: Request, res: Response) => {
    const currentDb = getDb();
    res.json({
      products: currentDb.products,
      categories: currentDb.categories,
      orders: currentDb.orders,
      purchases: currentDb.purchases,
      discounts: currentDb.discounts,
      reviews: currentDb.reviews,
      banners: currentDb.banners,
      settings: currentDb.settings,
      users: currentDb.users.map(sanitizeUser),
    });
  });

  // -------------------------------------------------------------
  // Authentication & Security API
  // -------------------------------------------------------------
  app.post('/api/auth/login', (req: Request, res: Response) => {
    const { email, password } = req.body || {};

    if (!email || !password) {
      res.status(400).json({ success: false, error: 'يرجى إدخال البريد الإلكتروني وكلمة المرور' });
      return;
    }

    const cleanEmail = email.trim().toLowerCase();

    // 1. Check account lockout
    const lockout = checkServerLockout(cleanEmail);
    if (lockout.isLocked) {
      res.status(429).json({
        success: false,
        isLocked: true,
        error: `تم تجميد الحساب مؤقتاً بسبب استنفاد محاولات الدخول الخاطئة. يرجى المحاولة بعد ${lockout.remainingMinutes} دقيقة.`,
      });
      return;
    }

    // 2. Find user
    const currentDb = getDb();
    const user = currentDb.users.find((u) => u.email.toLowerCase() === cleanEmail);

    if (!user) {
      const lockRes = recordFailedServerAttempt(cleanEmail);
      if (lockRes.isNowLocked) {
        res.status(429).json({
          success: false,
          isLocked: true,
          error: 'تم تجميد الحساب لمدة 15 دقيقة بعد 5 محاولات خاطئة متتالية.',
        });
        return;
      }
      res.status(401).json({
        success: false,
        error: `بيانات الدخول غير صحيحة. متبقي ${lockRes.remainingAttempts} محاولات قبل القفل المؤقت.`,
      });
      return;
    }

    // Check if account is inactive
    if (user.status === 'inactive') {
      res.status(403).json({ success: false, error: 'تم تعطيل هذا الحساب من قِبل الإدارة العامة.' });
      return;
    }

    // 3. Verify password hash using PBKDF2
    const isMatch = verifyPasswordServer(password, user.passwordHash);
    if (!isMatch) {
      const lockRes = recordFailedServerAttempt(cleanEmail);
      if (lockRes.isNowLocked) {
        res.status(429).json({
          success: false,
          isLocked: true,
          error: 'تم تجميد الحساب لمدة 15 دقيقة بعد 5 محاولات خاطئة متتالية.',
        });
        return;
      }
      res.status(401).json({
        success: false,
        error: `كلمة المرور غير صحيحة. متبقي ${lockRes.remainingAttempts} محاولات قبل القفل المؤقت.`,
      });
      return;
    }

    // 4. Success: Reset lockout & issue session token
    resetServerLockout(cleanEmail);
    const token = createServerSession(user);

    res.json({
      success: true,
      user: sanitizeUser(user),
      token,
    });
  });

  // Current session validation
  app.get('/api/auth/me', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';

    if (!token) {
      res.status(401).json({ success: false, error: 'لم يتم توفير رمز جلسة' });
      return;
    }

    const session = validateServerSession(token);
    if (!session) {
      res.status(401).json({ success: false, error: 'الجلسة منتهية الصلاحية أو غير صالحة' });
      return;
    }

    const currentDb = getDb();
    const user = currentDb.users.find((u) => u.id === session.userId);
    if (!user || user.status === 'inactive') {
      invalidateServerSession(token);
      res.status(401).json({ success: false, error: 'المستخدم غير موجود أو تم تعطيله' });
      return;
    }

    res.json({ success: true, user: sanitizeUser(user) });
  });

  // Logout
  app.post('/api/auth/logout', (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.startsWith('Bearer ') ? authHeader.substring(7) : '';
    if (token) {
      invalidateServerSession(token);
    }
    res.json({ success: true });
  });

  // Update Admin Credentials (Security tab)
  app.post('/api/auth/update-admin', (req: Request, res: Response) => {
    const { currentPassword, newEmail, newPassword } = req.body || {};

    if (!currentPassword) {
      res.status(400).json({ success: false, error: 'يرجى إدخال كلمة المرور الحالية لتأكيد الهوية' });
      return;
    }

    const currentDb = getDb();
    const adminIndex = currentDb.users.findIndex((u) => u.role === 'admin');
    if (adminIndex === -1) {
      res.status(404).json({ success: false, error: 'لم يتم العثور على حساب المدير العام' });
      return;
    }

    const admin = currentDb.users[adminIndex];

    // Verify current password on server
    const isCurrentValid = verifyPasswordServer(currentPassword, admin.passwordHash);
    if (!isCurrentValid) {
      res.status(401).json({ success: false, error: 'كلمة المرور الحالية غير صحيحة' });
      return;
    }

    let emailChanged = false;
    let passwordChanged = false;

    if (newEmail && newEmail.trim() && newEmail.trim().toLowerCase() !== admin.email.toLowerCase()) {
      admin.email = newEmail.trim().toLowerCase();
      emailChanged = true;
    }

    if (newPassword && newPassword.trim()) {
      admin.passwordHash = hashPasswordServer(newPassword.trim());
      passwordChanged = true;
    }

    // Save changes permanently to server database
    saveDb(currentDb);

    // If password changed, revoke all sessions to force re-login
    if (passwordChanged) {
      invalidateAllUserSessions(admin.id);
    }

    res.json({
      success: true,
      requireRelogin: passwordChanged,
      updatedEmail: admin.email,
      message: 'تم تحديث بيانات حساب المدير العام وحفظها في قاعدة البيانات المركزية بنجاح.',
    });
  });

  // -------------------------------------------------------------
  // Store Settings & Dynamic Logo API
  // -------------------------------------------------------------
  app.get('/api/settings', (_req: Request, res: Response) => {
    const currentDb = getDb();
    res.json(currentDb.settings);
  });

  app.put('/api/settings', (req: Request, res: Response) => {
    const currentDb = getDb();
    const newSettings = req.body as Partial<StoreSettings>;

    currentDb.settings = {
      ...currentDb.settings,
      ...newSettings,
    };

    saveDb(currentDb);
    res.json({ success: true, settings: currentDb.settings });
  });

  app.post('/api/upload-logo', (req: Request, res: Response) => {
    const { logoUrl } = req.body || {};
    if (!logoUrl) {
      res.status(400).json({ success: false, error: 'لم يتم توفير بيانات الشعار' });
      return;
    }

    const currentDb = getDb();
    currentDb.settings.logoUrl = logoUrl;
    saveDb(currentDb);

    res.json({ success: true, logoUrl, settings: currentDb.settings });
  });

  // -------------------------------------------------------------
  // Products CRUD API
  // -------------------------------------------------------------
  app.get('/api/products', (_req: Request, res: Response) => {
    res.json(getDb().products);
  });

  app.post('/api/products', (req: Request, res: Response) => {
    const currentDb = getDb();
    const newProduct = req.body as Product;

    if (!newProduct.id) {
      newProduct.id = `prod-${Date.now()}`;
    }
    if (!newProduct.createdAt) {
      newProduct.createdAt = new Date().toISOString();
    }

    currentDb.products.unshift(newProduct);
    saveDb(currentDb);
    res.json({ success: true, product: newProduct });
  });

  app.put('/api/products/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    const updated = req.body as Product;

    const idx = currentDb.products.findIndex((p) => p.id === id);
    if (idx === -1) {
      res.status(404).json({ success: false, error: 'المنتج غير موجود' });
      return;
    }

    currentDb.products[idx] = { ...currentDb.products[idx], ...updated };
    saveDb(currentDb);
    res.json({ success: true, product: currentDb.products[idx] });
  });

  app.delete('/api/products/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    currentDb.products = currentDb.products.filter((p) => p.id !== id);
    saveDb(currentDb);
    res.json({ success: true });
  });

  // -------------------------------------------------------------
  // Categories CRUD API
  // -------------------------------------------------------------
  app.get('/api/categories', (_req: Request, res: Response) => {
    res.json(getDb().categories);
  });

  app.post('/api/categories', (req: Request, res: Response) => {
    const currentDb = getDb();
    const cat = req.body as Category;
    if (!cat.id) cat.id = `cat-${Date.now()}`;
    currentDb.categories.push(cat);
    saveDb(currentDb);
    res.json({ success: true, category: cat });
  });

  app.put('/api/categories/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    const idx = currentDb.categories.findIndex((c) => c.id === id);
    if (idx === -1) {
      res.status(404).json({ success: false, error: 'القسم غير موجود' });
      return;
    }
    currentDb.categories[idx] = { ...currentDb.categories[idx], ...req.body };
    saveDb(currentDb);
    res.json({ success: true, category: currentDb.categories[idx] });
  });

  app.delete('/api/categories/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    currentDb.categories = currentDb.categories.filter((c) => c.id !== id);
    saveDb(currentDb);
    res.json({ success: true });
  });

  // -------------------------------------------------------------
  // Orders CRUD API
  // -------------------------------------------------------------
  app.get('/api/orders', (_req: Request, res: Response) => {
    res.json(getDb().orders);
  });

  app.post('/api/orders', (req: Request, res: Response) => {
    const currentDb = getDb();
    const order = req.body as Order;

    if (!order.id) order.id = `ord-${Date.now()}`;
    if (!order.orderNumber) order.orderNumber = `ZN-${new Date().getFullYear()}-${Math.floor(1000 + Math.random() * 9000)}`;
    if (!order.invoiceNumber) order.invoiceNumber = `INV-${new Date().getFullYear()}-${String(currentDb.orders.length + 1).padStart(4, '0')}`;
    if (!order.createdAt) order.createdAt = new Date().toISOString();

    // Deduct stock for ordered items
    order.items.forEach((item) => {
      const prod = currentDb.products.find((p) => p.id === item.productId);
      if (prod) {
        prod.stock = Math.max(0, prod.stock - item.quantity);
      }
    });

    currentDb.orders.unshift(order);
    saveDb(currentDb);
    res.json({ success: true, order });
  });

  app.put('/api/orders/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    const idx = currentDb.orders.findIndex((o) => o.id === id);
    if (idx === -1) {
      res.status(404).json({ success: false, error: 'الطلب غير موجود' });
      return;
    }
    currentDb.orders[idx] = { ...currentDb.orders[idx], ...req.body };
    saveDb(currentDb);
    res.json({ success: true, order: currentDb.orders[idx] });
  });

  // -------------------------------------------------------------
  // Supplier Purchases API
  // -------------------------------------------------------------
  app.get('/api/purchases', (_req: Request, res: Response) => {
    res.json(getDb().purchases);
  });

  app.post('/api/purchases', (req: Request, res: Response) => {
    const currentDb = getDb();
    const purchase = req.body as PurchaseInvoice;

    if (!purchase.id) purchase.id = `pur-${Date.now()}`;
    if (!purchase.createdAt) purchase.createdAt = new Date().toISOString();

    // If status is received, increase stock
    if (purchase.status === 'received') {
      purchase.items.forEach((item) => {
        const prod = currentDb.products.find((p) => p.id === item.productId);
        if (prod) {
          prod.stock += item.quantity;
          prod.costPrice = item.costPrice;
        }
      });
    }

    currentDb.purchases.unshift(purchase);
    saveDb(currentDb);
    res.json({ success: true, purchase });
  });

  app.delete('/api/purchases/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    currentDb.purchases = currentDb.purchases.filter((p) => p.id !== id);
    saveDb(currentDb);
    res.json({ success: true });
  });

  // -------------------------------------------------------------
  // Discounts / Coupons API
  // -------------------------------------------------------------
  app.get('/api/coupons', (_req: Request, res: Response) => {
    res.json(getDb().discounts);
  });

  app.post('/api/coupons', (req: Request, res: Response) => {
    const currentDb = getDb();
    const coupon = req.body as DiscountCoupon;
    if (!coupon.id) coupon.id = `disc-${Date.now()}`;
    currentDb.discounts.push(coupon);
    saveDb(currentDb);
    res.json({ success: true, coupon });
  });

  app.put('/api/coupons/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    const idx = currentDb.discounts.findIndex((d) => d.id === id);
    if (idx === -1) {
      res.status(404).json({ success: false, error: 'الكوبون غير موجود' });
      return;
    }
    currentDb.discounts[idx] = { ...currentDb.discounts[idx], ...req.body };
    saveDb(currentDb);
    res.json({ success: true, coupon: currentDb.discounts[idx] });
  });

  app.delete('/api/coupons/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    currentDb.discounts = currentDb.discounts.filter((d) => d.id !== id);
    saveDb(currentDb);
    res.json({ success: true });
  });

  // -------------------------------------------------------------
  // Reviews API
  // -------------------------------------------------------------
  app.get('/api/reviews', (_req: Request, res: Response) => {
    res.json(getDb().reviews);
  });

  app.post('/api/reviews', (req: Request, res: Response) => {
    const currentDb = getDb();
    const review = req.body as Review;
    if (!review.id) review.id = `rev-${Date.now()}`;
    if (!review.date) review.date = new Date().toISOString().split('T')[0];
    currentDb.reviews.unshift(review);
    saveDb(currentDb);
    res.json({ success: true, review });
  });

  app.put('/api/reviews/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    const idx = currentDb.reviews.findIndex((r) => r.id === id);
    if (idx === -1) {
      res.status(404).json({ success: false, error: 'التقييم غير موجود' });
      return;
    }
    currentDb.reviews[idx] = { ...currentDb.reviews[idx], ...req.body };
    saveDb(currentDb);
    res.json({ success: true, review: currentDb.reviews[idx] });
  });

  app.delete('/api/reviews/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    currentDb.reviews = currentDb.reviews.filter((r) => r.id !== id);
    saveDb(currentDb);
    res.json({ success: true });
  });

  // -------------------------------------------------------------
  // Banners API
  // -------------------------------------------------------------
  app.get('/api/banners', (_req: Request, res: Response) => {
    res.json(getDb().banners);
  });

  app.post('/api/banners', (req: Request, res: Response) => {
    const currentDb = getDb();
    const banner = req.body as Banner;
    if (!banner.id) banner.id = `ban-${Date.now()}`;
    currentDb.banners.push(banner);
    saveDb(currentDb);
    res.json({ success: true, banner });
  });

  app.put('/api/banners/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    const idx = currentDb.banners.findIndex((b) => b.id === id);
    if (idx === -1) {
      res.status(404).json({ success: false, error: 'البانر غير موجود' });
      return;
    }
    currentDb.banners[idx] = { ...currentDb.banners[idx], ...req.body };
    saveDb(currentDb);
    res.json({ success: true, banner: currentDb.banners[idx] });
  });

  app.delete('/api/banners/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    currentDb.banners = currentDb.banners.filter((b) => b.id !== id);
    saveDb(currentDb);
    res.json({ success: true });
  });

  // -------------------------------------------------------------
  // Staff & Users Management API (Section 2 - Staff Management)
  // -------------------------------------------------------------
  app.get('/api/users', (_req: Request, res: Response) => {
    const currentDb = getDb();
    res.json(currentDb.users.map(sanitizeUser));
  });

  app.post('/api/users', (req: Request, res: Response) => {
    const { name, email, password, role, phone, address, city } = req.body || {};

    if (!name || !email || !password) {
      res.status(400).json({ success: false, error: 'يرجى إدخال الاسم، البريد الإلكتروني، وكلمة المرور' });
      return;
    }

    const currentDb = getDb();
    const cleanEmail = email.trim().toLowerCase();

    if (currentDb.users.some((u) => u.email.toLowerCase() === cleanEmail)) {
      res.status(400).json({ success: false, error: 'هذا البريد الإلكتروني مسجل بالفعل لمستخدم آخر' });
      return;
    }

    const newUser: User = {
      id: `user-${Date.now()}`,
      name: name.trim(),
      email: cleanEmail,
      passwordHash: hashPasswordServer(password.trim()),
      role: role === 'admin' ? 'admin' : role === 'staff' ? 'staff' : 'customer',
      phone: phone || '',
      address: address || '',
      city: city || '',
      createdAt: new Date().toISOString(),
      status: 'active',
    };

    currentDb.users.push(newUser);
    saveDb(currentDb);

    res.json({ success: true, user: sanitizeUser(newUser) });
  });

  app.put('/api/users/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;
    const { name, email, role, status, phone, address, city, newPassword } = req.body || {};

    const idx = currentDb.users.findIndex((u) => u.id === id);
    if (idx === -1) {
      res.status(404).json({ success: false, error: 'المستخدم غير موجود' });
      return;
    }

    const user = currentDb.users[idx];

    // Prevent deactivating or demoting the main admin
    if (user.role === 'admin' && (status === 'inactive' || role !== 'admin')) {
      res.status(400).json({ success: false, error: 'لا يمكن تعطيل أو تغيير رتبة حساب المدير العام الرئيسي' });
      return;
    }

    if (name) user.name = name;
    if (email) user.email = email.trim().toLowerCase();
    if (role && user.role !== 'admin') user.role = role;
    if (status) user.status = status;
    if (phone !== undefined) user.phone = phone;
    if (address !== undefined) user.address = address;
    if (city !== undefined) user.city = city;
    if (newPassword && newPassword.trim()) {
      user.passwordHash = hashPasswordServer(newPassword.trim());
      invalidateAllUserSessions(user.id);
    }

    saveDb(currentDb);
    res.json({ success: true, user: sanitizeUser(user) });
  });

  app.delete('/api/users/:id', (req: Request, res: Response) => {
    const currentDb = getDb();
    const { id } = req.params;

    const user = currentDb.users.find((u) => u.id === id);
    if (!user) {
      res.status(404).json({ success: false, error: 'المستخدم غير موجود' });
      return;
    }

    if (user.role === 'admin') {
      res.status(400).json({ success: false, error: 'لا يمكن حذف حساب المدير العام الرئيسي' });
      return;
    }

    invalidateAllUserSessions(id);
    currentDb.users = currentDb.users.filter((u) => u.id !== id);
    saveDb(currentDb);

    res.json({ success: true });
  });

  // -------------------------------------------------------------
  // Backup & Restore API
  // -------------------------------------------------------------
  app.post('/api/admin/reset-data', (_req: Request, res: Response) => {
    const currentDb = getDb();
    // Keep the current admin credentials intact even across reset
    const currentAdmin = currentDb.users.find((u) => u.role === 'admin');

    // Fresh instance
    const freshDb = getDb();
    if (currentAdmin) {
      const idx = freshDb.users.findIndex((u) => u.role === 'admin');
      if (idx !== -1) {
        freshDb.users[idx] = currentAdmin;
      }
    }

    saveDb(freshDb);
    res.json({ success: true, message: 'تمت إعادة ضبط البيانات للمصنع بنجاح' });
  });

  app.post('/api/admin/restore-data', (req: Request, res: Response) => {
    const backup = req.body;
    if (!backup || !backup.products || !backup.settings) {
      res.status(400).json({ success: false, error: 'ملف النسخة الاحتياطية غير صالح أو ناقص' });
      return;
    }

    const currentDb = getDb();
    const currentAdmin = currentDb.users.find((u) => u.role === 'admin');

    currentDb.products = backup.products || currentDb.products;
    currentDb.categories = backup.categories || currentDb.categories;
    currentDb.orders = backup.orders || currentDb.orders;
    currentDb.purchases = backup.purchases || currentDb.purchases;
    currentDb.discounts = backup.discounts || currentDb.discounts;
    currentDb.reviews = backup.reviews || currentDb.reviews;
    currentDb.banners = backup.banners || currentDb.banners;
    currentDb.settings = backup.settings || currentDb.settings;

    if (backup.users && Array.isArray(backup.users)) {
      currentDb.users = backup.users;
      // Ensure admin exists
      if (!currentDb.users.some((u) => u.role === 'admin') && currentAdmin) {
        currentDb.users.unshift(currentAdmin);
      }
    }

    saveDb(currentDb);
    res.json({ success: true, message: 'تم استعادة النسخة الاحتياطية بنجاح' });
  });

  // -------------------------------------------------------------
  // Frontend Serving (Vite middleware in dev, Static dist in prod)
  // -------------------------------------------------------------
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[Zeina Store Backend] Server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('[Zeina Server] Failed to start server:', err);
});
