class MainController < ApplicationController
    def index
        render "hi", status: 200
    end
end