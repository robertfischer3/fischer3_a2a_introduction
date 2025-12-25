import graphviz

# Create a new directed graph
dot = graphviz.Digraph('Cryptocurrency_Agent', comment='Cryptocurrency Agent Flow', format='png')

# Set graph attributes for a professional look
# 'rankdir=LR' makes it flow Left-to-Right, which fits this specific diagram better than Top-Down
dot.attr(rankdir='LR', splines='ortho', pad='0.5', nodesep='0.8', ranksep='1.0', fontname='Helvetica', bgcolor='white')

# Set default node attributes
dot.attr('node', shape='rect', style='filled', penwidth='1.5', fontname='Helvetica', margin='0.2')

# Set default edge attributes
dot.attr('edge', color='#455A64', penwidth='1.5', arrowhead='vee', fontname='Helvetica', fontsize='10')

# --- Define Nodes ---

# Node 1: Client
dot.node('client', 'Client', fillcolor='#E3F2FD', color='#1565C0') # Blue theme

# Node 2: Price Oracle Agent
dot.node('oracle', 'Price Oracle Agent', fillcolor='#E8F5E9', color='#2E7D32') # Green theme

# Node 3: Price Generator
# Using HTML-like label for the subtitle "(stateless queries)"
label_gen = """<<b>Price Generator</b><br/><font point-size="10">(stateless queries)</font>>"""
dot.node('generator', label_gen, fillcolor='#FFF3E0', color='#EF6C00') # Orange theme

# --- Define Edges ---

# Edge 1: Client <--> Price Oracle Agent (TCP)
# dir='both' makes it a double-headed arrow
dot.edge('client', 'oracle', label='TCP', dir='both')

# Edge 2: Price Oracle Agent --> Price Generator
dot.edge('oracle', 'generator')

# Render the graph
dot.render('crypto_agent_diagram')