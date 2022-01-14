class ApplicationController < ActionController::API
    def index
        render "hi", status: 200
    end
end
