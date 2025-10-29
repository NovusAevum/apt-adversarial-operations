0 --port=443
    # In production: app.run(host='0.0.0.0', port=443, ssl_context=('cert.pem', 'key.pem'))
    
    # Development mode (HTTP only - not for production)
    app.run(host='0.0.0.0', port=8080, debug=False)
heartbeat       - Agent keep-alive
  GET  /api/tasks           - Retrieve pending tasks
  POST /api/results         - Submit task results
  GET  /api/agents          - List all agents (operator)
  POST /api/command         - Issue command to agent (operator)
")
    print()
    print("LEGAL WARNING:")
    print("  This C2 server is for AUTHORIZED testing only.")
    print("  Unauthorized use is ILLEGAL in most jurisdictions.")
    print("  Always obtain written permission before deployment.")
    print()
    print("=" * 70)
    print()
    
    # Initialize and run server
    server = C2Server()
    
    try:
        server.run(
            host=args.host,
            port=args.port,
            ssl_cert=args.cert,
            ssl_key=args.key
        )
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down gracefully...")
        logger.info("Server shutdown initiated by operator")
    except Exception as e:
        print(f"\n[ERROR] Server error: {e}")
        logger.error(f"Fatal server error: {e}")


if __name__ == "__main__":
    main()
