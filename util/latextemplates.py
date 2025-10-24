from string import Template

tikzplot = Template(
    r"""
            \addplot[
                $texlinewidth,
                $texlinestyle,
                color=$texcolor,
                mark=$texmark,
                mark options={solid,scale=$texmarkscale},
            ]
            coordinates {
                $coords
                };
            \addlegendentry{$texlegend}"""
)

tikzgraph = Template(
    r"""
%!TEX root = ./main.tex
% benchmarked on $hostname at $benchtimestamp
% tex generated at $gentimestamp
\begin{figure*}[t]
    \centering
    \footnotesize
    \begin{tikzpicture}
        \begin{axis}[
                xmode=$xmode,
                xlabel={$xlabel},
                ylabel={$ylabel},
                xtick={$xticks},
                xticklabels={$xticklabels},
                legend pos=$legendpos,
                legend cell align={left},
                ymajorgrids=true,
                grid style=dashed,
                width=$width,
                height=$height,
            ]

            $plots

        \end{axis}
    \end{tikzpicture}
    \caption{\fighead{$fighead} $caption}
    \label{$texlabel}
\end{figure*}
"""
)
