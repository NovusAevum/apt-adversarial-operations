0 --port=443
    # In production: app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
    
    # Development mode (HTTP only - not for production)
    app.run(host='0.0.0.0', port=8080, debug=False)
