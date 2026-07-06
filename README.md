# BillFree TechSupport - Cloudflare Pages

Secure login portal for BillFree TechSupport Operations Dashboard.

## Deployment to Cloudflare Pages

1. Go to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Navigate to **Workers & Pages** → **Create application** → **Pages**
3. Choose **Direct Upload**
4. Upload the contents of this folder
5. Set project name: `billfreetech`
6. Deploy!

## Configuration

Edit `index.html` to customize:

> Configuration lives in **`app.js`** (the `CONFIG` object near the top). The page
> script was externalized from `index.html` so the Content-Security-Policy no longer
> needs `script-src 'unsafe-inline'`.

### Allowed Users
Update the `ALLOWED_EMAILS` array in `app.js`:
```javascript
ALLOWED_EMAILS: [
    'neerajkumar.billfree@gmail.com',
    'suraj.billfree2@gmail.com',
    'veer.billfree@gmail.com',
    'gaurav.pal@billfree.in'  // Add more
]
```

### Apps Script Webapp URL
Update `WEBAPP_URL` in `app.js`:
```javascript
WEBAPP_URL: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec'
```

### Debug logging

`CONFIG.DEBUG` is `false` in production (no console output). Set it to `true` locally
to see auth-sync / session-bridge diagnostics.

## Security Features

- ✅ Google OAuth 2.0 authentication
- ✅ Email whitelist validation
- ✅ JWT token verification
- ✅ Session management with expiry
- ✅ Auto-redirect for returning users
