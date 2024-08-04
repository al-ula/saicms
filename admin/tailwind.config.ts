/** @type {import('tailwindcss').Config} */
import daisyui from "daisyui"
import catppuccin from "@catppuccin/daisyui"

export default {
  content: ["./templates/**/*.{html,hbs}", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {},
  },
  plugins: [
    daisyui,
  ],
  daisyui: {
    themes: [
      catppuccin("latte"), catppuccin("mocha"),
    ]
  }
}