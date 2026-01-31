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

### Allowed Users
Update the `ALLOWED_EMAILS` array (around line 290):
```javascript
ALLOWED_EMAILS: [
    'manjeetkashyap.billfree@gmail.com',
    'suraj.billfree2@gmail.com',
    'veer.billfree@gmail.com',
    'your-email@domain.com'  // Add more
]
```

### Apps Script Webapp URL
Update `WEBAPP_URL` (around line 300):
```javascript
WEBAPP_URL: 'https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec'
```

## Security Features

- ✅ Google OAuth 2.0 authentication
- ✅ Email whitelist validation
- ✅ JWT token verification
- ✅ Session management with expiry
- ✅ Auto-redirect for returning users
