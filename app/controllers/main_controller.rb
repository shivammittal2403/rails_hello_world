class MainController < ApplicationController
    def index
        render json:"hi", status: 200
    end
end