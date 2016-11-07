#ifndef CLIENT_HTTPS_HPP
#define	CLIENT_HTTPS_HPP

#include "client_http.hpp"
#include <boost/asio/ssl.hpp>

namespace SimpleWeb {
    typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> HTTPS;
    
    template<>
    class Client<HTTPS> : public ClientBase<HTTPS> {
    public:
        Client(const std::string& server_port_path, bool verify_certificate=true, 
                const std::string& cert_file=std::string(), const std::string& private_key_file=std::string(), 
                const std::string& verify_file=std::string()) : 
                ClientBase<HTTPS>::ClientBase(server_port_path, 443), context(boost::asio::ssl::context::tlsv12) {
            if(verify_certificate) {
                context.set_verify_mode(boost::asio::ssl::verify_peer);
                context.set_default_verify_paths();
            }
            else
                context.set_verify_mode(boost::asio::ssl::verify_none);
            
            if(cert_file.size()>0 && private_key_file.size()>0) {
                context.use_certificate_chain_file(cert_file);
                context.use_private_key_file(private_key_file, boost::asio::ssl::context::pem);
            }
            
            if(verify_file.size()>0)
                context.load_verify_file(verify_file);
            
            socket=std::make_shared<HTTPS>(io_service, context);
        }

        std::shared_ptr<Response> proxy_request(const std::string& proxyHost, int proxyPort, const std::string& request_type, const std::string& path="/", boost::string_ref content="",
                                                const std::map<std::string, std::string>& header=std::map<std::string, std::string>()) {
            return ClientBase::proxy_request(proxyHost, proxyPort, request_type, path, content.length(), [content](std::ostream& out) { out.write(content.data(), content.length()); }, header);
        }

    protected:
        boost::asio::ssl::context context;
        
        virtual void connect() override {
            if(socket_error || !socket->lowest_layer().is_open()) {
                boost::asio::ip::tcp::resolver::query query(host, std::to_string(port));
                boost::asio::connect(socket->lowest_layer(), resolver.resolve(query));
                
                boost::asio::ip::tcp::no_delay option(true);
                socket->lowest_layer().set_option(option);
                
                socket->handshake(boost::asio::ssl::stream_base::client);
                
                socket_error=false;
            }
        }

        /** Establishes an HTTPS connection through a proxy, using the connect method
         */
        virtual void proxy_connect(std::string proxyHost, int proxyPort) override {
            if(socket_error || !socket->lowest_layer().is_open()) {
                boost::asio::ip::tcp::resolver::query query(proxyHost, std::to_string(proxyPort));
                boost::asio::connect(socket->lowest_layer(), resolver.resolve(query));
                
                boost::asio::ip::tcp::no_delay option(true);
                socket->lowest_layer().set_option(option);

                //Request proxy to establish a connection to the target host
                std::string proxyPath = host + ":" + std::to_string(port);
                auto response = request(socket->next_layer(), "CONNECT", proxyPath, 0, [](std::ostream&) {});

                if (response->status_code.substr(0,3) != "200") {
                    socket_error = true;
                    throw std::logic_error("proxy_connect: Proxy denied connection with status code " + response->status_code);
                }
                //If no error happend, we can use the socket to start our ssl connection

                socket->handshake(boost::asio::ssl::stream_base::client);
                socket_error = false;
          }
        }
    };
}

#endif	/* CLIENT_HTTPS_HPP */
