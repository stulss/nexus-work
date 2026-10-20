"""Run the existing portal with the optional local monitoring bridge."""
from app import create_app
from app.monitoring import init_app
from app.realtime import socketio
from run import QuietHandler, parse_args

if __name__ == '__main__':
    args=parse_args()
    app=create_app()
    init_app(app)
    socketio.run(app,host=args.host,port=args.port,debug=False,use_reloader=False,
                 request_handler=QuietHandler,allow_unsafe_werkzeug=True)
