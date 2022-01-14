class MainController < ApplicationController
    def index
        render json:"success", status: 200
    end
end