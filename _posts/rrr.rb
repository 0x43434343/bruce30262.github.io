#!/usr/bin/env ruby

for f in Dir["./*.md"]
    first = true
    now  = ""
    File.readlines(f).each do |line|
        if first != false
            if line != "---\n"
                now  = "---\n"
            end
            first = false
        end
        if line.include?"author:"
            line = ""
        end
        now += line
    end
    File.open(f, 'w') { |file| file.write(now) }
end
